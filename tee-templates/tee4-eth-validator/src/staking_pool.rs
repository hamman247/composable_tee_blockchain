//! Staking pool — mirrors the LiquidStaking.sol contract logic in Rust.
//!
//! Shares-based model:
//! - Deposit ETH → receive teeETH shares proportional to exchange rate
//! - Exchange rate = totalPooledEther / totalSupply (increases as rewards accrue)
//! - 5% of rewards → treasury, 95% → increases teeETH backing
//! - Buffered ETH sits until ≥32 ETH → creates validator

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 32 ETH in wei.
const VALIDATOR_DEPOSIT: u128 = 32_000_000_000_000_000_000;

/// Maximum allowed treasury fee: 50% (5000 bps).
const MAX_TREASURY_FEE_BPS: u64 = 5000;

/// Maximum single deposit to prevent pool domination (10,000 ETH).
const MAX_DEPOSIT_WEI: u128 = 10_000_000_000_000_000_000_000;

/// Pool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Treasury address for the 5% fee.
    pub treasury: Address,
    /// Fee in basis points (500 = 5%). Capped at MAX_TREASURY_FEE_BPS.
    pub treasury_fee_bps: u64,
}

/// Staking pool error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// Deposit amount is zero.
    ZeroDeposit,
    /// Deposit exceeds maximum allowed.
    DepositTooLarge { amount: U256, max: U256 },
    /// Insufficient buffered ETH to create a validator.
    InsufficientBuffer { buffered: U256, required: U256 },
    /// Pool is in an invalid state (e.g., shares exist but no ETH backing).
    InvalidPoolState(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroDeposit => write!(f, "Cannot deposit zero ETH"),
            Self::DepositTooLarge { amount, max } =>
                write!(f, "Deposit {} exceeds max {}", amount, max),
            Self::InsufficientBuffer { buffered, required } =>
                write!(f, "Need {} buffered ETH, have {}", required, buffered),
            Self::InvalidPoolState(msg) => write!(f, "Invalid pool state: {}", msg),
        }
    }
}

/// Liquid staking pool state.
pub struct StakingPool {
    config: PoolConfig,
    /// teeETH balances (shares).
    shares: HashMap<Address, U256>,
    /// Total teeETH supply.
    total_shares: U256,
    /// Total ETH backing the shares (deposits + rewards - treasury cut).
    total_pooled_eth: U256,
    /// ETH buffered in the contract (not yet staked).
    buffered_eth: U256,
    /// Number of active validators.
    active_validators: u32,
    /// Total rewards ever reported.
    total_rewards: U256,
    /// Total sent to treasury.
    treasury_fees: U256,
}

impl StakingPool {
    pub fn new(config: PoolConfig) -> Self {
        // SECURITY: Clamp treasury fee to prevent excessive or overflowing fees
        let clamped_fee = config.treasury_fee_bps.min(MAX_TREASURY_FEE_BPS);
        if clamped_fee != config.treasury_fee_bps {
            tracing::warn!(
                "Treasury fee {} bps exceeds max {} bps, clamping",
                config.treasury_fee_bps, MAX_TREASURY_FEE_BPS
            );
        }
        Self {
            config: PoolConfig { treasury_fee_bps: clamped_fee, ..config },
            shares: HashMap::new(),
            total_shares: U256::ZERO, total_pooled_eth: U256::ZERO,
            buffered_eth: U256::ZERO, active_validators: 0,
            total_rewards: U256::ZERO, treasury_fees: U256::ZERO,
        }
    }

    /// Deposit ETH → receive teeETH shares. Returns shares minted.
    ///
    /// Returns an error instead of panicking on invalid inputs.
    pub fn deposit(&mut self, depositor: Address, eth_amount: U256) -> Result<U256, PoolError> {
        if eth_amount.is_zero() {
            return Err(PoolError::ZeroDeposit);
        }
        if eth_amount > U256::from(MAX_DEPOSIT_WEI) {
            return Err(PoolError::DepositTooLarge {
                amount: eth_amount,
                max: U256::from(MAX_DEPOSIT_WEI),
            });
        }

        let shares = if self.total_shares.is_zero() {
            eth_amount // First deposit: 1:1
        } else if self.total_pooled_eth.is_zero() {
            // SECURITY: Shares exist but no ETH backing — invalid state.
            // This could happen after a catastrophic slashing event.
            return Err(PoolError::InvalidPoolState(
                "Shares exist but total_pooled_eth is zero".to_string(),
            ));
        } else {
            (eth_amount * self.total_shares) / self.total_pooled_eth
        };

        self.total_pooled_eth += eth_amount;
        self.buffered_eth += eth_amount;
        self.total_shares += shares;
        *self.shares.entry(depositor).or_insert(U256::ZERO) += shares;

        Ok(shares)
    }

    /// Check if ≥32 ETH buffered.
    pub fn can_create_validator(&self) -> bool {
        self.buffered_eth >= U256::from(VALIDATOR_DEPOSIT)
    }

    /// Create a validator (deduct 32 ETH from buffer).
    /// Returns an error instead of panicking if insufficient buffer.
    pub fn create_validator(&mut self) -> Result<(), PoolError> {
        let required = U256::from(VALIDATOR_DEPOSIT);
        if self.buffered_eth < required {
            return Err(PoolError::InsufficientBuffer {
                buffered: self.buffered_eth,
                required,
            });
        }
        self.buffered_eth -= required;
        self.active_validators += 1;
        Ok(())
    }

    /// Report staking rewards: 5% → treasury shares, 95% → pool backing.
    pub fn report_rewards(&mut self, reward_amount: U256) {
        if reward_amount.is_zero() { return; }

        let treasury_fee = (reward_amount * U256::from(self.config.treasury_fee_bps)) / U256::from(10_000u64);
        let pool_increase = reward_amount - treasury_fee;

        self.total_rewards += reward_amount;
        self.treasury_fees += treasury_fee;
        self.total_pooled_eth += pool_increase;

        // Mint treasury shares at current rate
        if !treasury_fee.is_zero() && !self.total_pooled_eth.is_zero() {
            let treasury_shares = (treasury_fee * self.total_shares) / self.total_pooled_eth;
            if !treasury_shares.is_zero() {
                self.total_shares += treasury_shares;
                *self.shares.entry(self.config.treasury).or_insert(U256::ZERO) += treasury_shares;
            }
        }
    }

    /// Current exchange rate: ETH per teeETH (scaled by 1e18).
    pub fn exchange_rate(&self) -> U256 {
        if self.total_shares.is_zero() {
            return U256::from(1_000_000_000_000_000_000u128); // 1e18
        }
        (self.total_pooled_eth * U256::from(1_000_000_000_000_000_000u128)) / self.total_shares
    }

    pub fn exchange_rate_display(&self) -> String {
        let rate = self.exchange_rate();
        let whole = rate / U256::from(1_000_000_000_000_000_000u128);
        let frac = rate % U256::from(1_000_000_000_000_000_000u128);
        format!("{}.{:04}", whole, frac / U256::from(100_000_000_000_000u128))
    }

    /// How much ETH a given number of shares is worth.
    pub fn eth_for_shares(&self, share_amount: U256) -> U256 {
        if self.total_shares.is_zero() { return U256::ZERO; }
        (share_amount * self.total_pooled_eth) / self.total_shares
    }

    pub fn total_pooled_eth(&self) -> U256 { self.total_pooled_eth }
    pub fn buffered(&self) -> U256 { self.buffered_eth }
    pub fn total_rewards(&self) -> U256 { self.total_rewards }
    pub fn treasury_fees(&self) -> U256 { self.treasury_fees }
    pub fn staker_count(&self) -> usize { self.shares.len() }

    pub fn pending_validators(&self) -> u32 {
        (self.buffered_eth / U256::from(VALIDATOR_DEPOSIT)).to::<u32>()
    }

    pub fn share_balance(&self, addr: &Address) -> U256 {
        self.shares.get(addr).copied().unwrap_or(U256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(n: u64) -> U256 { U256::from(n) * U256::from(1_000_000_000_000_000_000u128) }

    fn test_pool() -> StakingPool {
        StakingPool::new(PoolConfig {
            treasury: Address::from([0xCC; 20]),
            treasury_fee_bps: 500,
        })
    }

    #[test]
    fn test_first_deposit_one_to_one() {
        let mut pool = test_pool();
        let shares = pool.deposit(Address::from([1;20]), eth(10)).unwrap();
        assert_eq!(shares, eth(10));
        assert_eq!(pool.total_pooled_eth(), eth(10));
        assert_eq!(pool.buffered(), eth(10));
    }

    #[test]
    fn test_multiple_deposits_same_rate() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(10)).unwrap();
        let shares = pool.deposit(Address::from([2;20]), eth(20)).unwrap();
        assert_eq!(shares, eth(20)); // Same rate before rewards
    }

    #[test]
    fn test_exchange_rate_increases_after_rewards() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(100)).unwrap();
        let rate_before = pool.exchange_rate();
        pool.report_rewards(eth(10));
        let rate_after = pool.exchange_rate();
        assert!(rate_after > rate_before, "Rate should increase");
    }

    #[test]
    fn test_deposit_after_rewards_fewer_shares() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(100)).unwrap();
        pool.report_rewards(eth(10));
        let shares = pool.deposit(Address::from([2;20]), eth(10)).unwrap();
        assert!(shares < eth(10), "Should get fewer shares after rewards");
    }

    #[test]
    fn test_treasury_gets_5pct() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(100)).unwrap();
        pool.report_rewards(eth(10));
        // Treasury fee = 5% of 10 = 0.5 ETH
        assert_eq!(pool.treasury_fees(), eth(10) / U256::from(20));
        // Pool increase = 95% of 10 = 9.5 ETH → total = 109.5
        let expected = eth(100) + eth(10) * U256::from(95) / U256::from(100);
        assert_eq!(pool.total_pooled_eth(), expected);
    }

    #[test]
    fn test_treasury_receives_shares() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(100)).unwrap();
        pool.report_rewards(eth(10));
        let treasury = Address::from([0xCC;20]);
        assert!(!pool.share_balance(&treasury).is_zero(), "Treasury should have shares");
    }

    #[test]
    fn test_create_validator_needs_32() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(31)).unwrap();
        assert!(!pool.can_create_validator());
        pool.deposit(Address::from([1;20]), eth(1)).unwrap();
        assert!(pool.can_create_validator());
    }

    #[test]
    fn test_create_validator_deducts_buffer() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(64)).unwrap();
        pool.create_validator().unwrap();
        assert_eq!(pool.buffered(), eth(32));
        assert_eq!(pool.active_validators, 1);
    }

    #[test]
    fn test_pending_validators() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(70)).unwrap();
        assert_eq!(pool.pending_validators(), 2);
    }

    #[test]
    fn test_eth_for_shares_increases() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(100)).unwrap();
        let before = pool.eth_for_shares(eth(100));
        pool.report_rewards(eth(10));
        let after = pool.eth_for_shares(eth(100));
        assert!(after > before, "Shares should be worth more after rewards");
    }

    #[test]
    fn test_staker_count() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(10)).unwrap();
        pool.deposit(Address::from([2;20]), eth(10)).unwrap();
        assert_eq!(pool.staker_count(), 2);
    }

    // ── New vulnerability-specific tests ──

    #[test]
    fn test_zero_deposit_rejected() {
        let mut pool = test_pool();
        assert_eq!(pool.deposit(Address::from([1;20]), U256::ZERO), Err(PoolError::ZeroDeposit));
    }

    #[test]
    fn test_oversized_deposit_rejected() {
        let mut pool = test_pool();
        let too_much = U256::from(MAX_DEPOSIT_WEI) + U256::from(1);
        assert!(matches!(
            pool.deposit(Address::from([1;20]), too_much),
            Err(PoolError::DepositTooLarge { .. })
        ));
    }

    #[test]
    fn test_create_validator_insufficient_buffer() {
        let mut pool = test_pool();
        pool.deposit(Address::from([1;20]), eth(20)).unwrap();
        assert!(matches!(
            pool.create_validator(),
            Err(PoolError::InsufficientBuffer { .. })
        ));
    }

    #[test]
    fn test_treasury_fee_clamped() {
        let pool = StakingPool::new(PoolConfig {
            treasury: Address::from([0xCC; 20]),
            treasury_fee_bps: 9999, // Way too high
        });
        assert_eq!(pool.config.treasury_fee_bps, MAX_TREASURY_FEE_BPS);
    }
}

