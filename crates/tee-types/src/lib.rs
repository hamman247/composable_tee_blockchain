//! Core types shared across the TEE-chain system.
//!
//! This crate defines all fundamental data structures used by the TEE-verified
//! blockchain including round messages, attestation evidence, TEE registrations,
//! and genesis configuration.

pub mod attestation;
pub mod config;
pub mod genesis;
pub mod round;
pub mod tee;

pub use attestation::*;
pub use config::*;
pub use genesis::*;
pub use round::*;
pub use tee::*;
