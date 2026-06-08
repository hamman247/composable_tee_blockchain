//! Attestation and certificate types.
//!
//! These types represent the chain of trust from Root Trust TEE
//! down to individual TEE instances.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::TeeId;

/// Certificate issued by the Root Trust TEE for a newly initialized TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootTrustCertificate {
    /// Version of the certificate format.
    pub version: u32,
    /// TEE ID of the certified TEE.
    pub subject_tee_id: TeeId,
    /// SHA3-256 hash of the TEE binary code.
    pub subject_code_hash: B256,
    /// ML-DSA public key of the certified TEE.
    pub subject_public_key: Vec<u8>,
    /// Timestamp when the certificate was issued.
    pub issued_at: u64,
    /// Timestamp when the certificate expires (0 = never).
    pub expires_at: u64,
    /// Root Trust TEE's ML-DSA signature over the certificate fields.
    pub root_trust_signature: Vec<u8>,
}

impl RootTrustCertificate {
    /// Get the bytes to be signed by the Root Trust TEE.
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(self.subject_tee_id.0.as_ref());
        bytes.extend_from_slice(self.subject_code_hash.as_ref());
        bytes.extend_from_slice(&self.subject_public_key);
        bytes.extend_from_slice(&self.issued_at.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        bytes
    }
}

/// Remote attestation evidence produced by a TEE.
/// Contains the attestation report and the certificate chain back to Root Trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// The TEE ID this evidence is for.
    pub tee_id: TeeId,
    /// Enclave measurement (hash of running code).
    pub enclave_measurement: B256,
    /// The certificate from Root Trust TEE.
    pub root_trust_cert: RootTrustCertificate,
    /// Additional TEE platform data (simulator or hardware-specific).
    pub platform_data: PlatformData,
    /// Nonce for replay protection.
    pub nonce: B256,
    /// Timestamp of evidence generation.
    pub timestamp: u64,
    /// Signature over all evidence fields by the TEE's own key.
    pub self_signature: Vec<u8>,
}

impl AttestationEvidence {
    /// Get the bytes to be signed by the TEE.
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.tee_id.0.as_ref());
        bytes.extend_from_slice(self.enclave_measurement.as_ref());
        bytes.extend_from_slice(&self.root_trust_cert.to_signing_bytes());
        bytes.extend_from_slice(&self.platform_data.to_bytes());
        bytes.extend_from_slice(self.nonce.as_ref());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }
}

/// Platform-specific attestation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformData {
    /// Simulator mode - contains simulated attestation report.
    Simulator {
        /// Simulated enclave report.
        report: Vec<u8>,
        /// Flag indicating this is simulator mode.
        simulator_version: String,
    },
    /// Production mode - contains real TEE platform attestation.
    Production {
        /// Platform attestation quote.
        quote: Vec<u8>,
        /// Platform-specific collateral.
        collateral: Vec<u8>,
    },
}

impl PlatformData {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("PlatformData serialization should not fail")
    }

    pub fn is_simulator(&self) -> bool {
        matches!(self, PlatformData::Simulator { .. })
    }
}

/// Result of verifying attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationResult {
    /// Attestation is valid, TEE is genuine.
    Valid,
    /// Attestation is valid but from simulator (accepted in dev mode only).
    ValidSimulator,
    /// Attestation failed verification.
    Invalid(String),
    /// Certificate has expired.
    Expired,
    /// Root Trust signature is invalid.
    InvalidRootTrust,
}

impl AttestationResult {
    pub fn is_acceptable(&self, allow_simulator: bool) -> bool {
        match self {
            AttestationResult::Valid => true,
            AttestationResult::ValidSimulator => allow_simulator,
            _ => false,
        }
    }
}
