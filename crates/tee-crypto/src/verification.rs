//! ML-DSA (Dilithium) signature verification using pqcrypto.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as PkTrait, DetachedSignature};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Verification failed: {0}")]
    Failed(String),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature format")]
    InvalidSignature,
}

/// Verify a Dilithium3 signature.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, VerificationError> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| VerificationError::InvalidPublicKey)?;
    let sig = dilithium3::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| VerificationError::InvalidSignature)?;
    Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
}

/// Verify a round-complete message signature.
pub fn verify_round_complete(
    public_key_bytes: &[u8],
    round_message: &tee_types::RoundCompleteMessage,
    signature_bytes: &[u8],
) -> Result<bool, VerificationError> {
    verify_signature(public_key_bytes, &round_message.to_signing_bytes(), signature_bytes)
}

/// Verify a Root Trust certificate signature.
pub fn verify_root_trust_certificate(
    root_trust_public_key: &[u8],
    certificate: &tee_types::RootTrustCertificate,
) -> Result<bool, VerificationError> {
    verify_signature(root_trust_public_key, &certificate.to_signing_bytes(), &certificate.root_trust_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PqcSigningKeypair, sign_message};

    #[test]
    fn test_sign_and_verify() {
        let kp = PqcSigningKeypair::generate().unwrap();
        let msg = b"test message for TEE-chain";
        let sig = sign_message(&kp, msg).unwrap();
        assert!(verify_signature(kp.public_key_bytes(), msg, &sig).unwrap());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = PqcSigningKeypair::generate().unwrap();
        let kp2 = PqcSigningKeypair::generate().unwrap();
        let sig = sign_message(&kp1, b"test").unwrap();
        assert!(!verify_signature(kp2.public_key_bytes(), b"test", &sig).unwrap());
    }

    #[test]
    fn test_tampered_message_fails() {
        let kp = PqcSigningKeypair::generate().unwrap();
        let sig = sign_message(&kp, b"original").unwrap();
        assert!(!verify_signature(kp.public_key_bytes(), b"tampered", &sig).unwrap());
    }
}
