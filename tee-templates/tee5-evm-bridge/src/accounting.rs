//! Per-user bridge accounting with nonce tracking.
//!
//! Each user has independent counters on each side of the bridge:
//! - `total_deposited` — cumulative tokens/coins deposited for bridging
//! - `total_received` — cumulative tokens/coins received from bridging
//! - `deposit_nonce` — monotonic counter for deposit operations
//! - `receive_nonce` — monotonic counter for receive/claim operations
//!
//! The claimable amount at any time is:
//!   claimable = total_deposited_on_source - total_received_on_destination

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum tracked users to prevent unbounded memory growth.
const MAX_TRACKED_USERS: usize = 10_000;

/// Per-user bridge state on one side of the bridge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserBridgeState {
    /// Total amount deposited for bridging (source side).
    pub total_deposited: U256,
    /// Total amount received from bridging (destination side).
    pub total_received: U256,
    /// Next deposit nonce (monotonically increasing).
    pub deposit_nonce: u64,
    /// Next receive/claim nonce.
    pub receive_nonce: u64,
    /// Timestamp of last interaction.
    pub last_active: u64,
}

impl UserBridgeState {
    /// Amount available to claim on the other side.
    pub fn claimable(&self) -> U256 {
        self.total_deposited.saturating_sub(self.total_received)
    }
}

/// A pending bridge deposit awaiting verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeposit {
    /// User who deposited.
    pub user: Address,
    /// Amount deposited (after fee).
    pub amount: U256,
    /// Deposit nonce on the source chain.
    pub nonce: u64,
    /// Timestamp when the deposit was observed/verified.
    pub verified_at: u64,
    /// Whether this has been included in a block.
    pub minted: bool,
}

/// A pending bridge burn awaiting cooldown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBurn {
    /// User who burned coins.
    pub user: Address,
    /// Amount burned (after fee).
    pub amount: U256,
    /// Burn nonce.
    pub nonce: u64,
    /// Timestamp when the burn was recorded.
    pub burned_at: u64,
    /// Whether the TEE has signed a withdrawal approval.
    pub approval_signed: bool,
}

/// Bridge accounting tracker.
#[derive(Debug)]
pub struct BridgeAccounting {
    /// Per-user state (source-side: deposits made by users on the remote chain).
    source_state: HashMap<Address, UserBridgeState>,
    /// Per-user state (destination-side: mints/receives on TEE-Chain).
    dest_state: HashMap<Address, UserBridgeState>,
    /// Pending deposits awaiting mint.
    pub pending_deposits: Vec<PendingDeposit>,
    /// Pending burns awaiting withdrawal approval.
    pub pending_burns: Vec<PendingBurn>,
    /// Bridge fee (in token/coin units, e.g. 0.1 = 100_000_000_000_000_000).
    pub bridge_fee: U256,
    /// Deposit finality time (seconds).
    pub deposit_finality_secs: u64,
    /// Burn cooldown time (seconds).
    pub burn_cooldown_secs: u64,
    /// Total fees collected.
    pub total_fees: U256,
}

/// Errors from accounting operations.
#[derive(Debug, Clone)]
pub enum AccountingError {
    InvalidNonce { expected: u64, got: u64 },
    InsufficientAmount { amount: U256, fee: U256 },
    DepositNotReady { elapsed: u64, required: u64 },
    BurnNotReady { elapsed: u64, required: u64 },
    UserNotFound(Address),
    AlreadyProcessed,
    PoolFull,
}

impl std::fmt::Display for AccountingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNonce { expected, got } =>
                write!(f, "Invalid nonce: expected {}, got {}", expected, got),
            Self::InsufficientAmount { amount, fee } =>
                write!(f, "Amount {} less than fee {}", amount, fee),
            Self::DepositNotReady { elapsed, required } =>
                write!(f, "Deposit not ready: {}s elapsed, {}s required", elapsed, required),
            Self::BurnNotReady { elapsed, required } =>
                write!(f, "Burn not ready: {}s elapsed, {}s required", elapsed, required),
            Self::UserNotFound(addr) => write!(f, "User not found: {}", addr),
            Self::AlreadyProcessed => write!(f, "Already processed"),
            Self::PoolFull => write!(f, "Tracking pool full"),
        }
    }
}

impl BridgeAccounting {
    pub fn new(bridge_fee: U256, deposit_finality_secs: u64, burn_cooldown_secs: u64) -> Self {
        Self {
            source_state: HashMap::new(),
            dest_state: HashMap::new(),
            pending_deposits: Vec::new(),
            pending_burns: Vec::new(),
            bridge_fee,
            deposit_finality_secs,
            burn_cooldown_secs,
            total_fees: U256::ZERO,
        }
    }

    /// Record a verified deposit from the source chain (Ethereum).
    /// Returns the net amount (after fee) and the assigned nonce.
    pub fn record_deposit(
        &mut self,
        user: Address,
        gross_amount: U256,
        now: u64,
    ) -> Result<(U256, u64), AccountingError> {
        if gross_amount <= self.bridge_fee {
            return Err(AccountingError::InsufficientAmount {
                amount: gross_amount,
                fee: self.bridge_fee,
            });
        }

        // DoS cap
        if !self.source_state.contains_key(&user) && self.source_state.len() >= MAX_TRACKED_USERS {
            return Err(AccountingError::PoolFull);
        }

        let net_amount = gross_amount - self.bridge_fee;
        self.total_fees += self.bridge_fee;

        let state = self.source_state.entry(user).or_default();
        let nonce = state.deposit_nonce;
        state.total_deposited += gross_amount;
        state.deposit_nonce += 1;
        state.last_active = now;

        self.pending_deposits.push(PendingDeposit {
            user,
            amount: net_amount,
            nonce,
            verified_at: now,
            minted: false,
        });

        Ok((net_amount, nonce))
    }

    /// Record a burn on TEE-Chain (user wants to bridge back).
    pub fn record_burn(
        &mut self,
        user: Address,
        gross_amount: U256,
        now: u64,
    ) -> Result<(U256, u64), AccountingError> {
        if gross_amount <= self.bridge_fee {
            return Err(AccountingError::InsufficientAmount {
                amount: gross_amount,
                fee: self.bridge_fee,
            });
        }

        if !self.dest_state.contains_key(&user) && self.dest_state.len() >= MAX_TRACKED_USERS {
            return Err(AccountingError::PoolFull);
        }

        let net_amount = gross_amount - self.bridge_fee;
        self.total_fees += self.bridge_fee;

        let state = self.dest_state.entry(user).or_default();
        let nonce = state.deposit_nonce; // burns are "deposits" on the dest side
        state.total_deposited += gross_amount;
        state.deposit_nonce += 1;
        state.last_active = now;

        self.pending_burns.push(PendingBurn {
            user,
            amount: net_amount,
            nonce,
            burned_at: now,
            approval_signed: false,
        });

        Ok((net_amount, nonce))
    }

    /// Get deposits ready to mint (past finality window).
    pub fn ready_deposits(&self, now: u64) -> Vec<&PendingDeposit> {
        self.pending_deposits.iter()
            .filter(|d| !d.minted && now.saturating_sub(d.verified_at) >= self.deposit_finality_secs)
            .collect()
    }

    /// Mark a deposit as minted and record the receive on destination side.
    pub fn mark_minted(&mut self, user: Address, nonce: u64) -> Result<U256, AccountingError> {
        let deposit = self.pending_deposits.iter_mut()
            .find(|d| d.user == user && d.nonce == nonce && !d.minted)
            .ok_or(AccountingError::AlreadyProcessed)?;

        deposit.minted = true;
        let amount = deposit.amount;

        // Record receive on destination
        let state = self.dest_state.entry(user).or_default();
        state.total_received += amount;
        state.receive_nonce += 1;

        Ok(amount)
    }

    /// Get burns ready for withdrawal approval (past cooldown).
    pub fn ready_burns(&self, now: u64) -> Vec<&PendingBurn> {
        self.pending_burns.iter()
            .filter(|b| !b.approval_signed && now.saturating_sub(b.burned_at) >= self.burn_cooldown_secs)
            .collect()
    }

    /// Mark a burn as having a signed approval.
    pub fn mark_approval_signed(&mut self, user: Address, nonce: u64) -> Result<U256, AccountingError> {
        let burn = self.pending_burns.iter_mut()
            .find(|b| b.user == user && b.nonce == nonce && !b.approval_signed)
            .ok_or(AccountingError::AlreadyProcessed)?;

        burn.approval_signed = true;
        let amount = burn.amount;

        // Record receive on source side (user will claim on Ethereum)
        let state = self.source_state.entry(user).or_default();
        state.total_received += amount;
        state.receive_nonce += 1;

        Ok(amount)
    }

    /// Get user's bridge state summary.
    pub fn user_summary(&self, user: &Address) -> (UserBridgeState, UserBridgeState) {
        (
            self.source_state.get(user).cloned().unwrap_or_default(),
            self.dest_state.get(user).cloned().unwrap_or_default(),
        )
    }

    /// Prune completed entries to prevent unbounded growth.
    pub fn prune_completed(&mut self) {
        self.pending_deposits.retain(|d| !d.minted);
        self.pending_burns.retain(|b| !b.approval_signed);
    }

    /// Total pending deposits.
    pub fn pending_deposit_count(&self) -> usize {
        self.pending_deposits.iter().filter(|d| !d.minted).count()
    }

    /// Total pending burns.
    pub fn pending_burn_count(&self) -> usize {
        self.pending_burns.iter().filter(|b| !b.approval_signed).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fee() -> U256 {
        U256::from(100_000_000_000_000_000u128) // 0.1
    }

    fn tokens(n: u64) -> U256 {
        U256::from(n) * U256::from(1_000_000_000_000_000_000u128)
    }

    #[test]
    fn test_deposit_deducts_fee() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        let (net, nonce) = acct.record_deposit(user, tokens(10), 1000).unwrap();
        assert_eq!(nonce, 0);
        assert_eq!(net, tokens(10) - fee());
    }

    #[test]
    fn test_deposit_too_small() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        let result = acct.record_deposit(user, fee(), 1000);
        assert!(matches!(result, Err(AccountingError::InsufficientAmount { .. })));
    }

    #[test]
    fn test_deposit_nonce_increments() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        let (_, n0) = acct.record_deposit(user, tokens(1), 1000).unwrap();
        let (_, n1) = acct.record_deposit(user, tokens(1), 1001).unwrap();
        assert_eq!(n0, 0);
        assert_eq!(n1, 1);
    }

    #[test]
    fn test_ready_deposits_respects_finality() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        acct.record_deposit(user, tokens(5), 1000).unwrap();

        // Not ready at 1500 (only 500s elapsed, need 600)
        assert_eq!(acct.ready_deposits(1500).len(), 0);
        // Ready at 1600 (600s elapsed)
        assert_eq!(acct.ready_deposits(1600).len(), 1);
    }

    #[test]
    fn test_mark_minted_records_receive() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        let (net, nonce) = acct.record_deposit(user, tokens(5), 1000).unwrap();
        acct.mark_minted(user, nonce).unwrap();

        let (_, dest) = acct.user_summary(&user);
        assert_eq!(dest.total_received, net);
        assert_eq!(dest.receive_nonce, 1);
    }

    #[test]
    fn test_burn_and_approval() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        let (net, nonce) = acct.record_burn(user, tokens(3), 2000).unwrap();

        // Not ready at 2200 (200s elapsed, need 300)
        assert_eq!(acct.ready_burns(2200).len(), 0);
        // Ready at 2300
        assert_eq!(acct.ready_burns(2300).len(), 1);

        let approved = acct.mark_approval_signed(user, nonce).unwrap();
        assert_eq!(approved, net);
    }

    #[test]
    fn test_double_mint_rejected() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        let (_, nonce) = acct.record_deposit(user, tokens(5), 1000).unwrap();
        acct.mark_minted(user, nonce).unwrap();
        assert!(matches!(acct.mark_minted(user, nonce), Err(AccountingError::AlreadyProcessed)));
    }

    #[test]
    fn test_prune_completed() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        acct.record_deposit(user, tokens(1), 100).unwrap();
        acct.record_deposit(user, tokens(1), 200).unwrap();
        acct.mark_minted(user, 0).unwrap();
        assert_eq!(acct.pending_deposits.len(), 2);
        acct.prune_completed();
        assert_eq!(acct.pending_deposits.len(), 1);
    }

    #[test]
    fn test_fee_accumulation() {
        let mut acct = BridgeAccounting::new(fee(), 600, 300);
        let user = Address::from([0x01; 20]);
        acct.record_deposit(user, tokens(5), 1000).unwrap();
        acct.record_burn(user, tokens(3), 2000).unwrap();
        assert_eq!(acct.total_fees, fee() * U256::from(2));
    }
}
