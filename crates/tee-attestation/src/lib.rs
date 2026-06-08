//! TEE Attestation verification.
//!
//! Verifies that attestation evidence chains back to the Root Trust TEE.
//! Supports both simulator and production attestation modes.

pub mod verifier;

pub use verifier::*;
