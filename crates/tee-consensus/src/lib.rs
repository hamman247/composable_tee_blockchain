//! TEE-based consensus engine for the EVM blockchain.
//!
//! Replaces traditional PoW/PoS with TEE-verified work:
//! blocks are valid only if they contain a valid TEE-signed
//! round-complete message with attestation chaining to Root Trust.

pub mod engine;
pub mod registry;

pub use engine::*;
pub use registry::*;
