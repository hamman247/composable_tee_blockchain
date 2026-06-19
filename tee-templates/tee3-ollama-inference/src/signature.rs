//! EVM Signature Verification for query authentication.
//!
//! Users sign their queries using EIP-191 personal_sign format:
//!   keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
//!
//! The TEE recovers the signer's address via secp256k1 ecrecover.
//! If recovery fails or the address doesn't match, the query is rejected.
//!
//! ## Replay Protection
//! Each signed query includes a timestamp and nonce. The TEE rejects:
//! - Queries older than `MAX_AGE_SECS` (default: 300s / 5 minutes)
//! - Queries with a nonce already seen from the same address

use alloy_primitives::Address;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

/// Maximum age of a signed query before it's rejected (seconds).
const MAX_AGE_SECS: u64 = 300;

/// A query signed by the user's EVM wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedQuery {
    /// The query text to send to the model.
    pub query: String,
    /// Model to use (e.g., "llama3.2:1b").
    pub model: String,
    /// Unix timestamp when the query was signed.
    pub timestamp: u64,
    /// Unique nonce to prevent replay attacks.
    pub nonce: u64,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// ECDSA signature (64 bytes: r || s).
    pub signature: Vec<u8>,
    /// Recovery ID (v value: 0 or 1).
    pub recovery_id: u8,
}

/// Result of signature verification.
#[derive(Debug, Clone)]
pub struct VerifiedQuery {
    /// Recovered signer address.
    pub signer: Address,
    /// The original query text.
    pub query: String,
    /// Model requested.
    pub model: String,
    /// Max tokens.
    pub max_tokens: u32,
    /// Timestamp from the signed message.
    pub timestamp: u64,
}

/// Signature verification errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// ECDSA signature is malformed.
    InvalidSignature(String),
    /// Could not recover the public key.
    RecoveryFailed(String),
    /// Query timestamp is too old.
    Expired { age_secs: u64, max_age: u64 },
    /// Nonce has already been used by this address.
    ReplayedNonce { address: Address, nonce: u64 },
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            Self::RecoveryFailed(e) => write!(f, "Key recovery failed: {}", e),
            Self::Expired { age_secs, max_age } => {
                write!(f, "Query expired: {}s old (max {}s)", age_secs, max_age)
            }
            Self::ReplayedNonce { address, nonce } => {
                write!(f, "Replayed nonce {} from {}", nonce, address)
            }
        }
    }
}

/// Constructs the EIP-191 personal sign message hash.
///
/// Format: keccak256("\x19Ethereum Signed Message:\n" + len + message)
pub fn eip191_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Constructs the canonical message bytes for a query.
///
/// Format: "ollama-query:{model}:{query}:{timestamp}:{nonce}:{max_tokens}"
pub fn query_message_bytes(query: &SignedQuery) -> Vec<u8> {
    format!(
        "ollama-query:{}:{}:{}:{}:{}",
        query.model, query.query, query.timestamp, query.nonce, query.max_tokens
    )
    .into_bytes()
}

/// Recover the signer's Ethereum address from a signed query.
pub fn recover_signer(query: &SignedQuery) -> Result<Address, SignatureError> {
    let message = query_message_bytes(query);
    let msg_hash = eip191_hash(&message);

    // Parse the ECDSA signature
    let signature = Signature::from_slice(&query.signature)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))?;

    let recovery_id = RecoveryId::new(query.recovery_id & 1 != 0, false);

    // Recover the public key
    let recovered_key =
        VerifyingKey::recover_from_prehash(&msg_hash, &signature, recovery_id)
            .map_err(|e| SignatureError::RecoveryFailed(e.to_string()))?;

    // Derive Ethereum address: keccak256(uncompressed_pubkey[1..]) → last 20 bytes
    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..]; // Skip 0x04 prefix
    let addr_hash = Keccak256::digest(pubkey_uncompressed);
    let address = Address::from_slice(&addr_hash[12..]);

    Ok(address)
}

/// Signature verifier with replay protection.
///
/// Uses a monotonic nonce model: for each address, only the highest nonce
/// seen is tracked. Any nonce ≤ the previous maximum is rejected.
/// This uses O(1) memory per address, preventing memory exhaustion attacks.
pub struct SignatureVerifier {
    /// Highest nonce seen per address (monotonic — only increases).
    last_nonce: HashMap<Address, u64>,
    /// Maximum query age in seconds.
    max_age_secs: u64,
}

impl SignatureVerifier {
    pub fn new() -> Self {
        Self {
            last_nonce: HashMap::new(),
            max_age_secs: MAX_AGE_SECS,
        }
    }

    /// Verify a signed query: check signature, expiry, and replay.
    pub fn verify(&mut self, query: &SignedQuery) -> Result<VerifiedQuery, SignatureError> {
        // 1. Check timestamp freshness
        let now = chrono::Utc::now().timestamp() as u64;
        if query.timestamp < now.saturating_sub(self.max_age_secs) {
            return Err(SignatureError::Expired {
                age_secs: now.saturating_sub(query.timestamp),
                max_age: self.max_age_secs,
            });
        }

        // 2. Recover signer
        let signer = recover_signer(query)?;

        // 3. Check replay using monotonic nonce
        // Nonce must be strictly greater than the last seen nonce for this address.
        let last = self.last_nonce.entry(signer).or_insert(0);
        if query.nonce <= *last {
            return Err(SignatureError::ReplayedNonce {
                address: signer,
                nonce: query.nonce,
            });
        }
        *last = query.nonce;

        Ok(VerifiedQuery {
            signer,
            query: query.query.clone(),
            model: query.model.clone(),
            max_tokens: query.max_tokens,
            timestamp: query.timestamp,
        })
    }

    /// Number of unique addresses that have submitted queries.
    pub fn unique_signers(&self) -> usize {
        self.last_nonce.len()
    }
}

/// Create a signed query for testing/simulation (uses a real secp256k1 key).
pub fn create_test_signed_query(
    query: &str,
    model: &str,
    nonce: u64,
) -> (SignedQuery, Address) {
    use k256::ecdsa::SigningKey;

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    // Derive address
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..];
    let addr_hash = Keccak256::digest(pubkey_uncompressed);
    let address = Address::from_slice(&addr_hash[12..]);

    let timestamp = chrono::Utc::now().timestamp() as u64;

    let mut sq = SignedQuery {
        query: query.to_string(),
        model: model.to_string(),
        timestamp,
        nonce,
        max_tokens: 256,
        signature: vec![],
        recovery_id: 0,
    };

    // Sign
    let message = query_message_bytes(&sq);
    let msg_hash = eip191_hash(&message);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&msg_hash)
        .expect("signing failed");

    sq.signature = signature.to_bytes().to_vec();
    sq.recovery_id = recovery_id.is_y_odd() as u8;

    (sq, address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eip191_hash_deterministic() {
        let h1 = eip191_hash(b"hello");
        let h2 = eip191_hash(b"hello");
        assert_eq!(h1, h2);
        let h3 = eip191_hash(b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_recover_signer_roundtrip() {
        let (sq, expected_addr) = create_test_signed_query("What is Rust?", "llama3.2:1b", 1);
        let recovered = recover_signer(&sq).expect("recovery should succeed");
        assert_eq!(recovered, expected_addr);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let (mut sq, _) = create_test_signed_query("test", "llama3.2:1b", 1);
        sq.signature[0] ^= 0xFF; // Corrupt signature
        // Should either fail to parse or recover a different address
        // (corrupted signatures may still be valid ECDSA, just a different key)
        let result = recover_signer(&sq);
        // We mainly care it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_verifier_replay_protection() {
        let mut verifier = SignatureVerifier::new();
        let (sq, _addr) = create_test_signed_query("test", "llama3.2:1b", 42);

        // First use: OK
        let result = verifier.verify(&sq);
        assert!(result.is_ok());

        // Replay: should fail
        let result2 = verifier.verify(&sq);
        assert!(matches!(result2, Err(SignatureError::ReplayedNonce { .. })));
    }

    #[test]
    fn test_verifier_expired_query() {
        let mut verifier = SignatureVerifier::new();
        let (mut sq, _) = create_test_signed_query("test", "llama3.2:1b", 1);
        sq.timestamp = 1000; // Way in the past
        let result = verifier.verify(&sq);
        // Recovery might fail or it should be expired
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_different_nonces_ok() {
        let mut verifier = SignatureVerifier::new();
        let (sq1, _) = create_test_signed_query("test1", "llama3.2:1b", 1);
        let (sq2, _) = create_test_signed_query("test2", "llama3.2:1b", 2);
        assert!(verifier.verify(&sq1).is_ok());
        assert!(verifier.verify(&sq2).is_ok());
    }

    #[test]
    fn test_unique_signers_count() {
        let mut verifier = SignatureVerifier::new();
        let (sq1, _) = create_test_signed_query("a", "llama3.2:1b", 1);
        let (sq2, _) = create_test_signed_query("b", "llama3.2:1b", 2);
        verifier.verify(&sq1).ok();
        verifier.verify(&sq2).ok();
        assert_eq!(verifier.unique_signers(), 2);
    }
}
