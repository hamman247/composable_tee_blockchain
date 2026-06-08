//! ML-DSA (Dilithium) message signing using pqcrypto.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{SecretKey as SkTrait, DetachedSignature};
use thiserror::Error;
use crate::PqcSigningKeypair;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Signing failed: {0}")]
    Failed(String),
    #[error("Invalid signing key")]
    InvalidKey,
}

/// Sign a message using Dilithium3.
pub fn sign_message(keypair: &PqcSigningKeypair, message: &[u8]) -> Result<Vec<u8>, SigningError> {
    let sk = dilithium3::SecretKey::from_bytes(keypair.private_key_bytes())
        .map_err(|e| SigningError::Failed(format!("Invalid secret key: {e}")))?;
    let sig = dilithium3::detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Sign a round-complete message.
pub fn sign_round_complete(
    keypair: &PqcSigningKeypair,
    round_message: &tee_types::RoundCompleteMessage,
) -> Result<Vec<u8>, SigningError> {
    sign_message(keypair, &round_message.to_signing_bytes())
}
