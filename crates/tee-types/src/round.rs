//! Round completion message types.
//!
//! When a TEE's internal logic declares a round finished, it signs a
//! `RoundCompleteMessage` with its sealed ML-DSA private key.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::TeeId;

/// Payment instruction from a TEE round completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentInstruction {
    /// Recipient address.
    pub recipient: Address,
    /// Amount to pay.
    pub amount: U256,
    /// Whether this is a block reward (vs. job payment).
    pub is_reward: bool,
}

/// The signed payload that a TEE produces when declaring a round complete.
/// This is the core data structure that triggers block production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundCompleteMessage {
    /// TEE identifier that produced this message.
    pub tee_id: TeeId,
    /// Monotonically increasing round identifier for this TEE.
    pub round_id: u64,
    /// Hash of the previous block.
    pub parent_block_hash: B256,
    /// Operator address(es) and payment amounts.
    pub payments: Vec<PaymentInstruction>,
    /// Block reward distributions (if mining-eligible).
    pub incentives: Vec<PaymentInstruction>,
    /// Timestamp when the round completed (inside the TEE).
    pub timestamp: u64,
    /// TEE-specific data (e.g., AI training metrics, compute measurements).
    pub tee_specific_data: Vec<u8>,
    /// Transactions to include in the block (transaction hashes).
    pub transaction_hashes: Vec<B256>,
}

impl RoundCompleteMessage {
    /// Serialize the message to bytes for signing.
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("RoundCompleteMessage serialization should not fail")
    }
}

/// A RoundCompleteMessage with its ML-DSA signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRoundComplete {
    /// The round completion message.
    pub message: RoundCompleteMessage,
    /// ML-DSA signature over the message bytes.
    pub signature: Vec<u8>,
    /// Remote attestation evidence for this TEE.
    pub attestation_evidence: Vec<u8>,
}

impl SignedRoundComplete {
    /// Serialize the entire signed message to bytes (for block extra-data).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SignedRoundComplete serialization should not fail")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
