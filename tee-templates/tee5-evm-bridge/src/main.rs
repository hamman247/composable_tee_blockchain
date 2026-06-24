//! TEE-5: EVM Cross-Chain Bridge
//!
//! Manages a trustless bridge between TEE-Chain and an EVM network
//! (Ethereum mainnet in production). The bridge enables 1:1 exchange
//! of an ERC20 token on Ethereum for the native gas coin on TEE-Chain.
//!
//! ## Bridge IN (Ethereum → TEE-Chain)
//! 1. User calls `depositForBridge(amount)` on BridgeEscrow.sol
//! 2. After 10 minutes, user notifies TEE-5
//! 3. TEE-5 verifies via multiple RPC nodes
//! 4. TEE-5 includes mint instruction in next block
//!
//! ## Bridge OUT (TEE-Chain → Ethereum)
//! 1. User burns native gas coins via BridgeVault.sol
//! 2. After 5 minutes, user requests withdrawal approval
//! 3. TEE-5 signs ECDSA message with its Ethereum wallet
//! 4. User claims on Ethereum by presenting the TEE signature
//!
//! ## Security
//! - Multi-RPC verification (2/3 consensus)
//! - ECDSA signature + calldata bytecode verification
//! - Per-user nonce tracking prevents replay
//! - Bridge fee (0.1 tokens, admin-adjustable) for sybil resistance

pub mod accounting;
pub mod rpc_verifier;

use tee_crypto::*;
use tee_types::*;
use alloy_primitives::{Address, B256, U256};
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};

use accounting::{BridgeAccounting, AccountingError};
use rpc_verifier::{RpcVerifier, RpcTxResponse, VerificationResult};

fn main() {
    println!("TEE-5 EVM Bridge — use as library or run local-testnet");
}

/// Default bridge fee: 0.1 tokens (in wei).
const DEFAULT_BRIDGE_FEE: u128 = 100_000_000_000_000_000; // 0.1 * 10^18

/// Default deposit finality: 10 minutes.
const DEFAULT_DEPOSIT_FINALITY_SECS: u64 = 600;

/// Default burn cooldown: 5 minutes.
const DEFAULT_BURN_COOLDOWN_SECS: u64 = 300;

/// A signed withdrawal approval from the TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalApproval {
    /// User who burned coins on TEE-Chain.
    pub user: Address,
    /// Amount to release on Ethereum (after fee).
    pub amount: U256,
    /// Withdrawal nonce.
    pub nonce: u64,
    /// TEE-5's ECDSA signature (EIP-191 personal_sign format).
    /// The smart contract verifies this against the registered teeSigner.
    pub signature: Vec<u8>,
    /// Recovery ID for ecrecover.
    pub recovery_id: u8,
    /// The message hash that was signed.
    pub message_hash: [u8; 32],
}

/// Bridge block data included in tee_specific_data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeBlockData {
    /// Number of deposits processed (minted) in this block.
    pub deposits_processed: u32,
    /// Number of withdrawal approvals signed in this block.
    pub approvals_signed: u32,
    /// Total value bridged in (minted) this block.
    pub total_minted: String,
    /// Total value bridged out (approved) this block.
    pub total_approved: String,
    /// Total fees collected.
    pub total_fees: String,
    /// Pending deposits awaiting finality.
    pub pending_deposits: usize,
    /// Pending burns awaiting cooldown.
    pub pending_burns: usize,
}

/// TEE-5 EVM Bridge Coordinator.
pub struct EvmBridgeTee {
    // ── Identity ──
    keypair: PqcSigningKeypair,
    tee_id: TeeId,
    code_hash: B256,
    certificate: RootTrustCertificate,

    // ── Ethereum ECDSA wallet ──
    /// secp256k1 signing key for Ethereum message signing.
    eth_signing_key: SigningKey,
    /// The TEE's Ethereum address (derived from the ECDSA public key).
    pub eth_address: Address,

    // ── Bridge state ──
    accounting: BridgeAccounting,
    rpc_verifier: RpcVerifier,

    // ── Mining ──
    round_id: u64,
    blocks_produced: u64,
    operator: Address,
    max_reward: U256,

    // ── Stats ──
    pub total_deposits: u64,
    pub total_burns: u64,
    pub total_approvals: u64,
}

impl EvmBridgeTee {
    pub fn new(
        keypair: PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
        certificate: RootTrustCertificate,
        escrow_contract: Address,
        operator: Address,
        max_reward: U256,
    ) -> Self {
        // Derive ECDSA key deterministically from PQC keypair seed.
        // In production, this would be sealed to the enclave.
        let seed_hash = Keccak256::digest(keypair.public_key_bytes());
        let eth_signing_key = SigningKey::from_bytes(
            k256::FieldBytes::from_slice(&seed_hash[..32])
        ).expect("Valid ECDSA key from deterministic seed");

        let eth_verifying_key = VerifyingKey::from(&eth_signing_key);
        let eth_address = Self::verifying_key_to_address(&eth_verifying_key);

        Self {
            keypair, tee_id, code_hash, certificate,
            eth_signing_key, eth_address,
            accounting: BridgeAccounting::new(
                U256::from(DEFAULT_BRIDGE_FEE),
                DEFAULT_DEPOSIT_FINALITY_SECS,
                DEFAULT_BURN_COOLDOWN_SECS,
            ),
            rpc_verifier: RpcVerifier::new(escrow_contract, DEFAULT_DEPOSIT_FINALITY_SECS),
            round_id: 0, blocks_produced: 0, operator, max_reward,
            total_deposits: 0, total_burns: 0, total_approvals: 0,
        }
    }

    /// Create a bridge TEE with custom timing (for testing).
    pub fn with_timing(
        keypair: PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
        certificate: RootTrustCertificate,
        escrow_contract: Address,
        operator: Address,
        max_reward: U256,
        bridge_fee: U256,
        deposit_finality_secs: u64,
        burn_cooldown_secs: u64,
    ) -> Self {
        let seed_hash = Keccak256::digest(keypair.public_key_bytes());
        let eth_signing_key = SigningKey::from_bytes(
            k256::FieldBytes::from_slice(&seed_hash[..32])
        ).expect("Valid ECDSA key");

        let eth_verifying_key = VerifyingKey::from(&eth_signing_key);
        let eth_address = Self::verifying_key_to_address(&eth_verifying_key);

        Self {
            keypair, tee_id, code_hash, certificate,
            eth_signing_key, eth_address,
            accounting: BridgeAccounting::new(bridge_fee, deposit_finality_secs, burn_cooldown_secs),
            rpc_verifier: RpcVerifier::new(escrow_contract, deposit_finality_secs),
            round_id: 0, blocks_produced: 0, operator, max_reward,
            total_deposits: 0, total_burns: 0, total_approvals: 0,
        }
    }

    /// Derive Ethereum address from a secp256k1 verifying key.
    fn verifying_key_to_address(key: &VerifyingKey) -> Address {
        let pubkey_bytes = key.to_encoded_point(false);
        let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..]; // skip 0x04 prefix
        let hash = Keccak256::digest(pubkey_uncompressed);
        Address::from_slice(&hash[12..])
    }

    // ── Bridge IN: Ethereum → TEE-Chain ──

    /// Verify a deposit from the source chain using multi-RPC consensus.
    pub fn verify_deposit(
        &mut self,
        rpc_responses: &[RpcTxResponse],
        claimed_user: Address,
        now: u64,
    ) -> Result<VerificationResult, String> {
        let result = self.rpc_verifier.verify_deposit(rpc_responses, claimed_user, now);

        if result.verified {
            self.accounting.record_deposit(claimed_user, result.amount, now)
                .map_err(|e| format!("Accounting error: {}", e))?;
            self.total_deposits += 1;
            Ok(result)
        } else {
            Err(format!(
                "Verification failed: {}/{} confirmations",
                result.confirmations, result.total_queried
            ))
        }
    }

    /// Simulate a verified deposit (for testnet — skips RPC verification).
    pub fn simulate_deposit(
        &mut self,
        user: Address,
        amount: U256,
        now: u64,
    ) -> Result<(U256, u64), AccountingError> {
        let result = self.accounting.record_deposit(user, amount, now)?;
        self.total_deposits += 1;
        Ok(result)
    }

    // ── Bridge OUT: TEE-Chain → Ethereum ──

    /// Record a coin burn on TEE-Chain.
    pub fn record_burn(
        &mut self,
        user: Address,
        amount: U256,
        now: u64,
    ) -> Result<(U256, u64), AccountingError> {
        let result = self.accounting.record_burn(user, amount, now)?;
        self.total_burns += 1;
        Ok(result)
    }

    /// Sign a withdrawal approval for burns past the cooldown period.
    /// Returns approvals that can be submitted to BridgeEscrow.sol on Ethereum.
    pub fn process_pending_approvals(&mut self, now: u64) -> Vec<WithdrawalApproval> {
        let ready: Vec<(Address, u64, U256)> = self.accounting.ready_burns(now)
            .iter()
            .map(|b| (b.user, b.nonce, b.amount))
            .collect();

        let mut approvals = Vec::new();
        for (user, nonce, amount) in ready {
            if let Ok(approved_amount) = self.accounting.mark_approval_signed(user, nonce) {
                if let Some(approval) = self.sign_withdrawal(user, approved_amount, nonce) {
                    approvals.push(approval);
                    self.total_approvals += 1;
                }
            }
        }
        approvals
    }

    /// Sign a withdrawal approval using the TEE's ECDSA key.
    fn sign_withdrawal(
        &self,
        user: Address,
        amount: U256,
        nonce: u64,
    ) -> Option<WithdrawalApproval> {
        // Construct the message to sign (matches Solidity verification):
        // keccak256(abi.encodePacked(user, amount, nonce, "TEE-BRIDGE-WITHDRAWAL"))
        let mut msg = Vec::new();
        msg.extend_from_slice(user.as_slice());
        msg.extend_from_slice(&amount.to_be_bytes::<32>());
        msg.extend_from_slice(&nonce.to_be_bytes());
        msg.extend_from_slice(b"TEE-BRIDGE-WITHDRAWAL");
        let msg_hash = Keccak256::digest(&msg);

        // EIP-191 personal_sign wrapper
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg_hash.len());
        let prefixed = Keccak256::digest(
            [prefix.as_bytes(), &msg_hash].concat()
        );

        // Sign with secp256k1
        let (signature, recovery_id) = self.eth_signing_key
            .sign_prehash_recoverable(&prefixed)
            .ok()?;

        Some(WithdrawalApproval {
            user,
            amount,
            nonce,
            signature: signature.to_bytes().to_vec(),
            recovery_id: recovery_id.to_byte(),
            message_hash: msg_hash.into(),
        })
    }

    // ── Block production ──

    /// Check if the bridge has work to include in a block.
    pub fn can_mine(&self, now: u64) -> bool {
        !self.accounting.ready_deposits(now).is_empty()
            || !self.accounting.ready_burns(now).is_empty()
    }

    /// Produce a bridge block: mint verified deposits and process approvals.
    pub fn produce_block(
        &mut self,
        parent_hash: B256,
        now: u64,
    ) -> Result<SignedRoundComplete, Box<dyn std::error::Error>> {
        self.round_id += 1;

        // Process ready deposits → mint instructions
        let ready_deposits: Vec<(Address, u64, U256)> = self.accounting.ready_deposits(now)
            .iter()
            .map(|d| (d.user, d.nonce, d.amount))
            .collect();

        let mut incentives = Vec::new();
        let mut deposits_processed = 0u32;
        let mut total_minted = U256::ZERO;

        for (user, nonce, amount) in ready_deposits {
            if let Ok(minted) = self.accounting.mark_minted(user, nonce) {
                let capped = if minted > self.max_reward { self.max_reward } else { minted };
                incentives.push(PaymentInstruction {
                    recipient: user,
                    amount: capped,
                    is_reward: false, // mint, not reward
                });
                deposits_processed += 1;
                total_minted += minted;
            }
        }

        // Process ready burns → sign approvals
        let approvals = self.process_pending_approvals(now);
        let approvals_signed = approvals.len() as u32;
        let total_approved: U256 = approvals.iter().map(|a| a.amount).sum();

        // Operator reward for bridge operation
        let operator_reward = U256::from(1_000_000_000_000_000_000u128); // 1 TEEC
        incentives.push(PaymentInstruction {
            recipient: self.operator,
            amount: operator_reward,
            is_reward: true,
        });

        let block_data = BridgeBlockData {
            deposits_processed,
            approvals_signed,
            total_minted: total_minted.to_string(),
            total_approved: total_approved.to_string(),
            total_fees: self.accounting.total_fees.to_string(),
            pending_deposits: self.accounting.pending_deposit_count(),
            pending_burns: self.accounting.pending_burn_count(),
        };

        let tee_data = serde_json::to_vec(&block_data)?;

        let msg = RoundCompleteMessage {
            tee_id: self.tee_id,
            round_id: self.round_id,
            parent_block_hash: parent_hash,
            payments: vec![],
            incentives,
            timestamp: now,
            tee_specific_data: tee_data,
            transaction_hashes: vec![],
        };

        let sig = sign_message(&self.keypair, &msg.to_signing_bytes())?;
        let mut evidence = AttestationEvidence {
            tee_id: self.tee_id,
            enclave_measurement: self.code_hash,
            root_trust_cert: self.certificate.clone(),
            platform_data: PlatformData::Simulator {
                report: vec![0u8; 64],
                simulator_version: "2.0.0".to_string(),
            },
            nonce: B256::random(),
            timestamp: now,
            self_signature: vec![],
        };
        evidence.self_signature = sign_message(&self.keypair, &evidence.to_signing_bytes())?;

        // Cleanup
        self.accounting.prune_completed();
        self.blocks_produced += 1;

        Ok(SignedRoundComplete {
            message: msg,
            signature: sig,
            attestation_evidence: bincode::serialize(&evidence)?,
        })
    }

    // ── Accessors ──

    pub fn blocks_produced(&self) -> u64 {
        self.blocks_produced
    }

    pub fn pending_deposit_count(&self) -> usize {
        self.accounting.pending_deposit_count()
    }

    pub fn pending_burn_count(&self) -> usize {
        self.accounting.pending_burn_count()
    }

    pub fn total_fees(&self) -> U256 {
        self.accounting.total_fees
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::RecoveryId;

    fn setup_tee() -> EvmBridgeTee {
        let kp = PqcSigningKeypair::generate().unwrap();
        let tee_id = TeeId::new([0x55; 32]);
        let code_hash = B256::from([0x55; 32]);

        let cert = RootTrustCertificate {
            version: 1,
            subject_tee_id: tee_id,
            subject_code_hash: code_hash,
            subject_public_key: kp.public_key_bytes().to_vec(),
            issued_at: chrono::Utc::now().timestamp() as u64,
            expires_at: 0,
            root_trust_signature: vec![0u8; 100],
        };

        let escrow = Address::from([0xEE; 20]);
        let operator = Address::from([0x05; 20]);

        EvmBridgeTee::with_timing(
            kp, tee_id, code_hash, cert, escrow, operator,
            U256::from(100_000_000_000_000_000_000u128), // 100 max reward
            U256::from(100_000_000_000_000_000u128),     // 0.1 fee
            10, // 10s finality (fast for testing)
            5,  // 5s cooldown (fast for testing)
        )
    }

    #[test]
    fn test_eth_address_derivation() {
        let tee = setup_tee();
        // Should have a valid 20-byte address
        assert_ne!(tee.eth_address, Address::ZERO);
        println!("TEE-5 Ethereum address: {}", tee.eth_address);
    }

    #[test]
    fn test_simulate_deposit() {
        let mut tee = setup_tee();
        let user = Address::from([0x01; 20]);
        let amount = U256::from(5_000_000_000_000_000_000u128);

        let (net, nonce) = tee.simulate_deposit(user, amount, 1000).unwrap();
        assert_eq!(nonce, 0);
        assert_eq!(net, amount - U256::from(100_000_000_000_000_000u128));
        assert_eq!(tee.total_deposits, 1);
    }

    #[test]
    fn test_deposit_and_mint_flow() {
        let mut tee = setup_tee();
        let user = Address::from([0x01; 20]);
        let amount = U256::from(10_000_000_000_000_000_000u128); // 10 tokens

        // Deposit at t=100
        tee.simulate_deposit(user, amount, 100).unwrap();

        // Not ready at t=105 (only 5s elapsed, need 10)
        assert!(!tee.can_mine(105));

        // Ready at t=110
        assert!(tee.can_mine(110));

        // Produce block
        let block = tee.produce_block(B256::ZERO, 110).unwrap();
        assert!(!block.message.incentives.is_empty());

        // Mint recipient should be the user
        assert_eq!(block.message.incentives[0].recipient, user);
    }

    #[test]
    fn test_burn_and_approval_flow() {
        let mut tee = setup_tee();
        let user = Address::from([0x01; 20]);
        let amount = U256::from(3_000_000_000_000_000_000u128); // 3 coins

        // Burn at t=200
        let (net, nonce) = tee.record_burn(user, amount, 200).unwrap();
        assert_eq!(nonce, 0);
        assert_eq!(tee.total_burns, 1);

        // Not ready at t=204 (4s elapsed, need 5)
        assert!(tee.accounting.ready_burns(204).is_empty());

        // Ready at t=205
        assert_eq!(tee.accounting.ready_burns(205).len(), 1);

        // Process approvals
        let approvals = tee.process_pending_approvals(205);
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].user, user);
        assert_eq!(approvals[0].amount, net);
        assert_eq!(approvals[0].nonce, 0);
        assert!(!approvals[0].signature.is_empty());
    }

    #[test]
    fn test_withdrawal_signature_verification() {
        let tee = setup_tee();
        let user = Address::from([0x01; 20]);
        let amount = U256::from(1_000_000_000_000_000_000u128);

        let approval = tee.sign_withdrawal(user, amount, 0).unwrap();

        // Verify we can recover the TEE's address from the signature
        let prefix = format!("\x19Ethereum Signed Message:\n{}", 32);
        let prefixed = Keccak256::digest(
            [prefix.as_bytes(), &approval.message_hash].concat()
        );

        let sig = k256::ecdsa::Signature::from_slice(&approval.signature).unwrap();
        let rid = RecoveryId::from_byte(approval.recovery_id).unwrap();
        let recovered = VerifyingKey::recover_from_prehash(&prefixed, &sig, rid).unwrap();
        let recovered_addr = EvmBridgeTee::verifying_key_to_address(&recovered);

        assert_eq!(recovered_addr, tee.eth_address);
    }

    #[test]
    fn test_multi_user_bridge() {
        let mut tee = setup_tee();
        let user_a = Address::from([0x0A; 20]);
        let user_b = Address::from([0x0B; 20]);

        // Two users deposit
        tee.simulate_deposit(user_a, U256::from(5_000_000_000_000_000_000u128), 100).unwrap();
        tee.simulate_deposit(user_b, U256::from(8_000_000_000_000_000_000u128), 102).unwrap();

        assert_eq!(tee.pending_deposit_count(), 2);

        // Both ready after finality
        let block = tee.produce_block(B256::ZERO, 120).unwrap();
        // Should have mints for both users + operator reward
        assert_eq!(block.message.incentives.len(), 3);
    }

    #[test]
    fn test_nonce_isolation() {
        let mut tee = setup_tee();
        let user = Address::from([0x01; 20]);
        let amt = U256::from(2_000_000_000_000_000_000u128);

        // Deposits get nonces 0, 1, 2
        let (_, n0) = tee.simulate_deposit(user, amt, 100).unwrap();
        let (_, n1) = tee.simulate_deposit(user, amt, 101).unwrap();
        let (_, n2) = tee.simulate_deposit(user, amt, 102).unwrap();
        assert_eq!((n0, n1, n2), (0, 1, 2));

        // Burns get their own nonce sequence
        let (_, bn0) = tee.record_burn(user, amt, 200).unwrap();
        let (_, bn1) = tee.record_burn(user, amt, 201).unwrap();
        assert_eq!((bn0, bn1), (0, 1));
    }

    #[test]
    fn test_full_roundtrip() {
        let mut tee = setup_tee();
        let user = Address::from([0x01; 20]);
        let deposit_amount = U256::from(10_000_000_000_000_000_000u128); // 10

        // 1. Deposit on Ethereum → verified by TEE
        let (net_in, _) = tee.simulate_deposit(user, deposit_amount, 100).unwrap();

        // 2. Wait finality → produce block → user gets native coins
        let _block = tee.produce_block(B256::ZERO, 115).unwrap();
        assert_eq!(tee.blocks_produced(), 1);

        // 3. User burns coins on TEE-Chain
        let (net_out, _) = tee.record_burn(user, net_in, 200).unwrap();

        // 4. Wait cooldown → get approval
        let approvals = tee.process_pending_approvals(206);
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].amount, net_out);

        // 5. Fees collected for both legs
        let expected_fees = U256::from(100_000_000_000_000_000u128) * U256::from(2);
        assert_eq!(tee.total_fees(), expected_fees);
    }
}
