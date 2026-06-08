//! Key sealing using pqcrypto-kyber for key encapsulation.
//!
//! ## Security Model
//!
//! Key sealing separates the **sealed blob** (safe to write to disk, opaque to the
//! creator) from the **provisioning key** (held exclusively inside the Root Trust
//! TEE enclave). The creator never sees the KEM decapsulation key that protects
//! the child TEE's signing key.
//!
//! ### Sealed blob (written to disk by Root Trust)
//! Contains: KEM ciphertext, encrypted signing key, public key, integrity hash.
//! Does NOT contain: KEM decapsulation key.
//!
//! ### Provisioning flow
//! 1. Root Trust generates child TEE keypair inside its enclave
//! 2. Root Trust seals child key — the dk (decapsulation key) stays in Root Trust memory
//! 3. Root Trust stores sealed blob to disk (creator can see this, but it's useless alone)
//! 4. Child TEE starts and generates an ephemeral Kyber KEM keypair
//! 5. Child TEE sends ephemeral public key to Root Trust over a provisioning channel
//! 6. Root Trust encapsulates the dk into the ephemeral public key → ciphertext + shared secret
//! 7. Root Trust encrypts the dk with the shared secret and sends the ciphertext + encrypted dk
//! 8. Child TEE decapsulates with its ephemeral secret key → shared secret → decrypts dk
//! 9. Child TEE uses dk to unseal its signing keypair from the sealed blob
//! 10. Child TEE destroys the ephemeral secret key and dk — only the unsealed keypair remains

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as PkTrait, SecretKey as SkTrait, Ciphertext as CtTrait, SharedSecret as SsTrait};
use sha3::{Sha3_256, Digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::PqcSigningKeypair;

#[derive(Error, Debug)]
pub enum SealingError {
    #[error("Sealing failed: {0}")]
    SealFailed(String),
    #[error("Unsealing failed: {0}")]
    UnsealFailed(String),
    #[error("Provisioning failed: {0}")]
    ProvisionFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Sealed key material — safe to store on disk.
/// **Does NOT contain the decapsulation key.** Without the dk,
/// the encrypted_signing_key is computationally infeasible to recover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyMaterial {
    /// KEM ciphertext (Kyber768 encapsulation output).
    pub kem_ciphertext: Vec<u8>,
    /// KEM public key (used during sealing; included for metadata only).
    pub kem_public_key: Vec<u8>,
    /// The ML-DSA signing key, encrypted under a key derived from the KEM shared secret.
    pub encrypted_signing_key: Vec<u8>,
    /// The ML-DSA public key (not secret).
    pub public_key: Vec<u8>,
    /// SHA3-256(signing_key || public_key) — integrity check after unsealing.
    pub integrity_hash: Vec<u8>,
}

/// The decapsulation key — MUST be kept inside the Root Trust TEE enclave.
/// This is never written to a file that the creator/operator can access.
///
/// ## Security invariants
/// - NOT `Clone` — prevents duplication of the dk
/// - NOT `Serialize`/`Deserialize` — prevents serialization to disk or wire
/// - `Debug` is redacted — prevents logging the dk
/// - `ZeroizeOnDrop` — zeroes dk from memory when dropped
/// - `dk_bytes()` is `pub(crate)` — only tee-crypto internals can read the dk
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProvisioningSecret {
    /// Raw KEM decapsulation key bytes.
    dk_bytes: Vec<u8>,
}

impl ProvisioningSecret {
    /// Access dk bytes. CRATE-INTERNAL ONLY.
    pub(crate) fn dk_bytes(&self) -> &[u8] {
        &self.dk_bytes
    }
}

impl std::fmt::Debug for ProvisioningSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningSecret")
            .field("dk_bytes", &"[REDACTED]")
            .finish()
    }
}

/// Provisioning request from a child TEE to Root Trust.
/// The child generates an ephemeral Kyber keypair and sends the public half.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningRequest {
    /// The child TEE's ephemeral KEM public key.
    pub ephemeral_public_key: Vec<u8>,
}

/// Provisioning response from Root Trust to a child TEE.
/// Contains the dk encrypted under the ephemeral shared secret,
/// so only the child TEE (who holds the ephemeral secret key) can decrypt it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningResponse {
    /// KEM ciphertext for the ephemeral key exchange.
    pub ephemeral_ciphertext: Vec<u8>,
    /// The dk encrypted with the ephemeral shared secret.
    pub encrypted_dk: Vec<u8>,
    /// Integrity hash over the dk.
    pub dk_integrity_hash: Vec<u8>,
}

/// Ephemeral keypair held by the child TEE during provisioning.
/// The secret key is destroyed after provisioning completes.
///
/// ## Security invariants
/// - NOT `Clone` — prevents duplication
/// - NOT `Serialize`/`Deserialize` — prevents serialization
/// - `Debug` is redacted
/// - `ZeroizeOnDrop` — zeroes secret key from memory when dropped
/// - `secret_key_bytes` is private — only accessible via crate-internal functions
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralProvisioningKeypair {
    #[zeroize(skip)] // Public key is not secret
    pub(crate) public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

impl std::fmt::Debug for EphemeralProvisioningKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralProvisioningKeypair")
            .field("public_key_len", &self.public_key_bytes.len())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

// ────────────────────────────────────────────────────────────────────────
// Core sealing / unsealing (used inside Root Trust enclave)
// ────────────────────────────────────────────────────────────────────────

/// Seal a keypair using Kyber768 KEM.
/// Returns the sealed blob (safe to export) and the provisioning secret (MUST stay in enclave).
pub fn seal_keypair(keypair: &PqcSigningKeypair) -> Result<(SealedKeyMaterial, ProvisioningSecret), SealingError> {
    let (pk, sk) = kyber768::keypair();
    let (ss, ct) = kyber768::encapsulate(&pk);

    // Derive encryption key from shared secret
    let enc_key = derive_key(ss.as_bytes(), b"tee-chain-key-sealing-v1");

    // XOR encrypt the signing key
    let encrypted = xor_encrypt(keypair.private_key_bytes(), &enc_key);

    let mut ih = Sha3_256::new();
    ih.update(keypair.private_key_bytes());
    ih.update(keypair.public_key_bytes());

    Ok((
        SealedKeyMaterial {
            kem_ciphertext: ct.as_bytes().to_vec(),
            kem_public_key: pk.as_bytes().to_vec(),
            encrypted_signing_key: encrypted,
            public_key: keypair.public_key_bytes().to_vec(),
            integrity_hash: ih.finalize().to_vec(),
        },
        ProvisioningSecret {
            dk_bytes: sk.as_bytes().to_vec(),
        },
    ))
}

/// Unseal a keypair given the provisioning secret.
/// Called inside the child TEE enclave after receiving the dk via provisioning.
pub fn unseal_keypair(sealed: &SealedKeyMaterial, secret: &ProvisioningSecret) -> Result<PqcSigningKeypair, SealingError> {
    unseal_keypair_with_dk(sealed, &secret.dk_bytes)
}

/// Low-level unseal using raw dk bytes (used internally during provisioning).
fn unseal_keypair_with_dk(sealed: &SealedKeyMaterial, dk_bytes: &[u8]) -> Result<PqcSigningKeypair, SealingError> {
    let sk = kyber768::SecretKey::from_bytes(dk_bytes)
        .map_err(|e| SealingError::UnsealFailed(format!("Invalid KEM secret key: {e}")))?;
    let ct = kyber768::Ciphertext::from_bytes(&sealed.kem_ciphertext)
        .map_err(|e| SealingError::UnsealFailed(format!("Invalid ciphertext: {e}")))?;

    let ss = kyber768::decapsulate(&ct, &sk);
    let enc_key = derive_key(ss.as_bytes(), b"tee-chain-key-sealing-v1");

    let signing_key_bytes = xor_encrypt(&sealed.encrypted_signing_key, &enc_key);

    let mut ih = Sha3_256::new();
    ih.update(&signing_key_bytes);
    ih.update(&sealed.public_key);
    if ih.finalize().to_vec() != sealed.integrity_hash {
        return Err(SealingError::UnsealFailed("Integrity check failed".into()));
    }

    PqcSigningKeypair::from_bytes(&signing_key_bytes, &sealed.public_key)
        .map_err(|e| SealingError::UnsealFailed(format!("Key reconstruction: {e}")))
}

// ────────────────────────────────────────────────────────────────────────
// Secure provisioning channel (Root Trust ↔ Child TEE)
// ────────────────────────────────────────────────────────────────────────

/// Child TEE: generate an ephemeral KEM keypair for the provisioning handshake.
pub fn create_provisioning_request() -> Result<(ProvisioningRequest, EphemeralProvisioningKeypair), SealingError> {
    let (pk, sk) = kyber768::keypair();
    Ok((
        ProvisioningRequest {
            ephemeral_public_key: pk.as_bytes().to_vec(),
        },
        EphemeralProvisioningKeypair {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        },
    ))
}

/// Root Trust: respond to a provisioning request by encrypting the dk under the
/// child TEE's ephemeral public key.
/// The creator/operator CANNOT decrypt this because they don't hold the ephemeral secret key.
pub fn create_provisioning_response(
    secret: &ProvisioningSecret,
    request: &ProvisioningRequest,
) -> Result<ProvisioningResponse, SealingError> {
    let eph_pk = kyber768::PublicKey::from_bytes(&request.ephemeral_public_key)
        .map_err(|e| SealingError::ProvisionFailed(format!("Invalid ephemeral PK: {e}")))?;

    // Encapsulate: produces shared secret + ciphertext
    let (ss, ct) = kyber768::encapsulate(&eph_pk);

    // Encrypt the dk under the channel shared secret
    let channel_key = derive_key(ss.as_bytes(), b"tee-chain-provisioning-v1");
    let encrypted_dk = xor_encrypt(&secret.dk_bytes, &channel_key);

    let mut dkh = Sha3_256::new();
    dkh.update(&secret.dk_bytes);

    Ok(ProvisioningResponse {
        ephemeral_ciphertext: ct.as_bytes().to_vec(),
        encrypted_dk,
        dk_integrity_hash: dkh.finalize().to_vec(),
    })
}

/// Child TEE: receive a provisioning response and extract the dk.
/// After this, destroy the ephemeral keypair — the dk is all we need to unseal.
pub fn receive_provisioning_response(
    response: &ProvisioningResponse,
    ephemeral: &EphemeralProvisioningKeypair,
) -> Result<ProvisioningSecret, SealingError> {
    let eph_sk = kyber768::SecretKey::from_bytes(&ephemeral.secret_key_bytes)
        .map_err(|e| SealingError::ProvisionFailed(format!("Invalid ephemeral SK: {e}")))?;
    let ct = kyber768::Ciphertext::from_bytes(&response.ephemeral_ciphertext)
        .map_err(|e| SealingError::ProvisionFailed(format!("Invalid ciphertext: {e}")))?;

    // Decapsulate to recover the channel shared secret
    let ss = kyber768::decapsulate(&ct, &eph_sk);
    let channel_key = derive_key(ss.as_bytes(), b"tee-chain-provisioning-v1");

    // Decrypt the dk
    let dk_bytes = xor_encrypt(&response.encrypted_dk, &channel_key);

    // Verify integrity
    let mut dkh = Sha3_256::new();
    dkh.update(&dk_bytes);
    if dkh.finalize().to_vec() != response.dk_integrity_hash {
        return Err(SealingError::ProvisionFailed("DK integrity check failed — possible interception".into()));
    }

    Ok(ProvisioningSecret { dk_bytes })
}

// ────────────────────────────────────────────────────────────────────────
// File I/O — sealed blobs ONLY (no secrets!)
// ────────────────────────────────────────────────────────────────────────

/// Save the sealed key material to disk.
/// The provisioning secret (dk) is NOT included — it stays in the Root Trust enclave.
pub fn save_sealed_blob(sealed: &SealedKeyMaterial, path: &str) -> Result<(), SealingError> {
    std::fs::write(path, serde_json::to_string_pretty(sealed).unwrap())?;
    Ok(())
}

/// Load a sealed key blob from disk. Returns only the opaque sealed material.
/// The child TEE must obtain the dk via the provisioning channel to unseal.
pub fn load_sealed_blob(path: &str) -> Result<SealedKeyMaterial, SealingError> {
    let data: SealedKeyMaterial = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| SealingError::UnsealFailed(e.to_string()))?;
    Ok(data)
}

// ────────────────────────────────────────────────────────────────────────
// DEPRECATED — kept only for Root Trust self-sealing (its own key)
// ────────────────────────────────────────────────────────────────────────

/// Save sealed keys WITH the dk — ONLY for Root Trust's own keypair.
/// This is acceptable because the Root Trust TEE seals its own key for restart
/// persistence, and the Root Trust enclave is the most privileged entity.
pub fn save_sealed_keys_self(sealed: &SealedKeyMaterial, secret: &ProvisioningSecret, path: &str) -> Result<(), SealingError> {
    let data = SelfSealedFile { sealed: sealed.clone(), dk_bytes: secret.dk_bytes().to_vec() };
    std::fs::write(path, serde_json::to_string_pretty(&data).unwrap())?;
    Ok(())
}

/// Load self-sealed keys — ONLY for Root Trust's own keypair.
pub fn load_sealed_keys_self(path: &str) -> Result<(SealedKeyMaterial, ProvisioningSecret), SealingError> {
    let data: SelfSealedFile = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| SealingError::UnsealFailed(e.to_string()))?;
    Ok((data.sealed, ProvisioningSecret { dk_bytes: data.dk_bytes }))
}

#[derive(Serialize, Deserialize)]
struct SelfSealedFile { sealed: SealedKeyMaterial, dk_bytes: Vec<u8> }

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

fn derive_key(shared_secret: &[u8], domain: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret);
    hasher.update(domain);
    hasher.finalize().to_vec()
}

fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut ks = Vec::new();
    let mut ctr = 0u64;
    while ks.len() < data.len() {
        let mut h = Sha3_256::new();
        h.update(key);
        h.update(&ctr.to_le_bytes());
        ks.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    for (i, b) in data.iter().enumerate() {
        result.push(b ^ ks[i]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let kp = PqcSigningKeypair::generate().unwrap();
        let orig_pub = kp.public_key_bytes().to_vec();
        let orig_priv = kp.private_key_bytes().to_vec();
        let (sealed, secret) = seal_keypair(&kp).unwrap();
        let recovered = unseal_keypair(&sealed, &secret).unwrap();
        assert_eq!(recovered.public_key_bytes(), &orig_pub[..]);
        assert_eq!(recovered.private_key_bytes(), &orig_priv[..]);
    }

    #[test]
    fn test_tampered_sealed_fails() {
        let kp = PqcSigningKeypair::generate().unwrap();
        let (mut sealed, secret) = seal_keypair(&kp).unwrap();
        if !sealed.encrypted_signing_key.is_empty() {
            sealed.encrypted_signing_key[0] ^= 0xFF;
        }
        assert!(unseal_keypair(&sealed, &secret).is_err());
    }

    #[test]
    fn test_sealed_blob_without_dk_is_useless() {
        // Verify that the sealed blob alone cannot recover the key
        let kp = PqcSigningKeypair::generate().unwrap();
        let (sealed, _secret) = seal_keypair(&kp).unwrap();

        // Try to unseal with a WRONG dk — should fail
        let (_, wrong_secret) = seal_keypair(&kp).unwrap();
        let result = unseal_keypair(&sealed, &wrong_secret);
        assert!(result.is_err(), "Sealed blob must not be unsealable with wrong dk");
    }

    #[test]
    fn test_provisioning_channel_roundtrip() {
        let kp = PqcSigningKeypair::generate().unwrap();
        let orig_pub = kp.public_key_bytes().to_vec();
        let orig_priv = kp.private_key_bytes().to_vec();

        // Root Trust seals the keypair
        let (sealed, secret) = seal_keypair(&kp).unwrap();

        // Child TEE creates provisioning request
        let (request, ephemeral) = create_provisioning_request().unwrap();

        // Root Trust creates provisioning response (encrypts dk for child)
        let response = create_provisioning_response(&secret, &request).unwrap();

        // Child TEE receives the response and extracts dk
        let recovered_secret = receive_provisioning_response(&response, &ephemeral).unwrap();

        // Child TEE unseals with the recovered dk
        let recovered_kp = unseal_keypair(&sealed, &recovered_secret).unwrap();
        assert_eq!(recovered_kp.public_key_bytes(), &orig_pub[..]);
        assert_eq!(recovered_kp.private_key_bytes(), &orig_priv[..]);
    }

    #[test]
    fn test_intercepted_provisioning_response_fails() {
        let kp = PqcSigningKeypair::generate().unwrap();
        let (_, secret) = seal_keypair(&kp).unwrap();

        // Child TEE creates request
        let (request, _ephemeral) = create_provisioning_request().unwrap();

        // Root Trust creates response
        let response = create_provisioning_response(&secret, &request).unwrap();

        // Attacker creates their OWN ephemeral keypair (doesn't match the request)
        let (_attacker_request, attacker_ephemeral) = create_provisioning_request().unwrap();

        // Attacker tries to decrypt with their own ephemeral key — MUST fail
        let result = receive_provisioning_response(&response, &attacker_ephemeral);
        assert!(result.is_err(), "Intercepted response must not be decryptable");
    }
}
