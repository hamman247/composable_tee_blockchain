//! ML-DSA (Dilithium) keypair generation using pqcrypto.
//!
//! ## Security hardening
//!
//! - `PqcSigningKeypair` does NOT implement `Debug`, `Serialize`, or `Deserialize`
//! - The private key bytes are NOT accessible via any public method
//! - Key material is zeroized on drop (defense in depth)
//! - Only the `sign_message` function in the `signing` module can access private key bytes
//!   (via a crate-internal accessor)
//! - No external crate can read, clone, or serialize the signing key

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as PkTrait, SecretKey as SkTrait};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum KeypairError {
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),
    #[error("Invalid key bytes: {0}")]
    InvalidKeyBytes(String),
}

/// A ML-DSA (Dilithium3) signing keypair.
///
/// ## Security invariants
/// - The private key bytes are NEVER exposed via public API
/// - `Debug` prints a redacted placeholder — NEVER the actual key
/// - `Clone` is deliberately NOT implemented — keys cannot be duplicated
/// - `Serialize`/`Deserialize` are deliberately NOT implemented
/// - On drop, all key material is zeroized from memory
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqcSigningKeypair {
    signing_key_bytes: Vec<u8>,
    #[zeroize(skip)] // Public key is not secret
    verifying_key_bytes: Vec<u8>,
}

impl PqcSigningKeypair {
    /// Generate a new Dilithium3 keypair.
    pub fn generate() -> Result<Self, KeypairError> {
        let (pk, sk) = dilithium3::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let sk_bytes = sk.as_bytes().to_vec();
        tracing::info!(pk_len = pk_bytes.len(), "Generated Dilithium3 keypair");
        Ok(Self { signing_key_bytes: sk_bytes, verifying_key_bytes: pk_bytes })
    }

    /// Reconstruct from raw bytes. ONLY called inside tee-crypto during unsealing.
    pub(crate) fn from_bytes(signing_key: &[u8], verifying_key: &[u8]) -> Result<Self, KeypairError> {
        Ok(Self {
            signing_key_bytes: signing_key.to_vec(),
            verifying_key_bytes: verifying_key.to_vec(),
        })
    }

    /// Get the public verification key bytes. This is NOT secret.
    pub fn public_key_bytes(&self) -> &[u8] { &self.verifying_key_bytes }

    /// Access the private signing key bytes.
    /// CRATE-INTERNAL ONLY — not accessible from outside tee-crypto.
    /// Used by `signing::sign_message` and `sealing::seal_keypair`.
    pub(crate) fn private_key_bytes(&self) -> &[u8] { &self.signing_key_bytes }
}

/// Custom Debug implementation that NEVER prints key material.
impl std::fmt::Debug for PqcSigningKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcSigningKeypair")
            .field("public_key_len", &self.verifying_key_bytes.len())
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcPublicKey {
    pub key_bytes: Vec<u8>,
}

impl PqcPublicKey {
    pub fn from_keypair(keypair: &PqcSigningKeypair) -> Self {
        Self { key_bytes: keypair.verifying_key_bytes.clone() }
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { key_bytes: bytes }
    }
}
