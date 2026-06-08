//! Attestation evidence verifier.
//!
//! Verifies the full chain of trust from a TEE's attestation evidence
//! back to the Root Trust TEE's public key.

use tee_crypto::verify_signature;
use tee_types::{AttestationEvidence, AttestationResult, RootTrustCertificate, TeeMode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Verification error: {0}")]
    VerificationError(String),
    #[error("Invalid evidence format: {0}")]
    InvalidFormat(String),
    #[error("Certificate chain broken: {0}")]
    BrokenChain(String),
}

/// Attestation verifier that validates evidence against the Root Trust TEE.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    /// Root Trust TEE's ML-DSA public key.
    root_trust_public_key: Vec<u8>,
    /// Whether simulator attestations are accepted.
    allow_simulator: bool,
}

impl AttestationVerifier {
    /// Create a new verifier with the Root Trust public key.
    pub fn new(root_trust_public_key: Vec<u8>, mode: TeeMode) -> Self {
        Self {
            root_trust_public_key,
            allow_simulator: mode == TeeMode::Simulator,
        }
    }

    /// Verify attestation evidence and return the result.
    pub fn verify(&self, evidence: &AttestationEvidence) -> Result<AttestationResult, AttestationError> {
        // Step 1: Verify the Root Trust certificate signature
        let cert = &evidence.root_trust_cert;
        let cert_valid = self.verify_root_trust_cert(cert)?;
        if !cert_valid {
            return Ok(AttestationResult::InvalidRootTrust);
        }

        // Step 2: Check certificate hasn't expired
        if cert.expires_at > 0 {
            let now = chrono::Utc::now().timestamp() as u64;
            if now > cert.expires_at {
                return Ok(AttestationResult::Expired);
            }
        }

        // Step 3: Verify the TEE ID matches the certificate subject
        if evidence.tee_id != cert.subject_tee_id {
            return Ok(AttestationResult::Invalid(
                "TEE ID mismatch between evidence and certificate".to_string(),
            ));
        }

        // Step 4: Verify the enclave measurement matches the certificate code hash
        if evidence.enclave_measurement != cert.subject_code_hash {
            return Ok(AttestationResult::Invalid(
                "Enclave measurement does not match certified code hash".to_string(),
            ));
        }

        // Step 5: Verify the TEE's self-signature over the evidence
        let evidence_bytes = evidence.to_signing_bytes();
        let self_sig_valid = verify_signature(
            &cert.subject_public_key,
            &evidence_bytes,
            &evidence.self_signature,
        )
        .map_err(|e| AttestationError::VerificationError(format!("Self-signature verification: {e}")))?;

        if !self_sig_valid {
            return Ok(AttestationResult::Invalid(
                "TEE self-signature is invalid".to_string(),
            ));
        }

        // Step 6: Check platform data type
        if evidence.platform_data.is_simulator() {
            if self.allow_simulator {
                tracing::warn!(tee_id = %evidence.tee_id, "Accepting SIMULATOR attestation");
                Ok(AttestationResult::ValidSimulator)
            } else {
                Ok(AttestationResult::Invalid(
                    "Simulator attestation not accepted in production mode".to_string(),
                ))
            }
        } else {
            Ok(AttestationResult::Valid)
        }
    }

    /// Verify a Root Trust certificate's signature.
    fn verify_root_trust_cert(&self, cert: &RootTrustCertificate) -> Result<bool, AttestationError> {
        let cert_bytes = cert.to_signing_bytes();
        verify_signature(
            &self.root_trust_public_key,
            &cert_bytes,
            &cert.root_trust_signature,
        )
        .map_err(|e| AttestationError::VerificationError(format!("Root Trust cert verification: {e}")))
    }

    /// Verify that a given public key is certified by the Root Trust TEE.
    pub fn verify_tee_public_key(
        &self,
        public_key: &[u8],
        certificate: &RootTrustCertificate,
    ) -> Result<bool, AttestationError> {
        // First verify the certificate itself
        let cert_valid = self.verify_root_trust_cert(certificate)?;
        if !cert_valid {
            return Ok(false);
        }

        // Then check the public key matches the certificate subject
        Ok(public_key == certificate.subject_public_key)
    }

    /// Get the Root Trust public key.
    pub fn root_trust_public_key(&self) -> &[u8] {
        &self.root_trust_public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use tee_crypto::{PqcSigningKeypair, sign_message};
    use tee_types::{PlatformData, TeeId};

    fn create_test_root_trust() -> PqcSigningKeypair {
        PqcSigningKeypair::generate().unwrap()
    }

    fn create_test_certificate(
        root_keypair: &PqcSigningKeypair,
        subject_keypair: &PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
    ) -> RootTrustCertificate {
        let mut cert = RootTrustCertificate {
            version: 1,
            subject_tee_id: tee_id,
            subject_code_hash: code_hash,
            subject_public_key: subject_keypair.public_key_bytes().to_vec(),
            issued_at: chrono::Utc::now().timestamp() as u64,
            expires_at: 0,
            root_trust_signature: vec![],
        };
        let cert_bytes = cert.to_signing_bytes();
        cert.root_trust_signature = sign_message(root_keypair, &cert_bytes).unwrap();
        cert
    }

    fn create_test_evidence(
        subject_keypair: &PqcSigningKeypair,
        cert: RootTrustCertificate,
        tee_id: TeeId,
        code_hash: B256,
    ) -> AttestationEvidence {
        let mut evidence = AttestationEvidence {
            tee_id,
            enclave_measurement: code_hash,
            root_trust_cert: cert,
            platform_data: PlatformData::Simulator {
                report: vec![0u8; 64],
                simulator_version: "1.0.0".to_string(),
            },
            nonce: B256::random(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            self_signature: vec![],
        };
        let evidence_bytes = evidence.to_signing_bytes();
        evidence.self_signature = sign_message(subject_keypair, &evidence_bytes).unwrap();
        evidence
    }

    #[test]
    fn test_valid_attestation() {
        let root_kp = create_test_root_trust();
        let tee_kp = PqcSigningKeypair::generate().unwrap();
        let tee_id = TeeId::new([1u8; 32]);
        let code_hash = B256::from([2u8; 32]);

        let cert = create_test_certificate(&root_kp, &tee_kp, tee_id, code_hash);
        let evidence = create_test_evidence(&tee_kp, cert, tee_id, code_hash);

        let verifier = AttestationVerifier::new(
            root_kp.public_key_bytes().to_vec(),
            TeeMode::Simulator,
        );

        let result = verifier.verify(&evidence).unwrap();
        assert!(result.is_acceptable(true));
    }

    #[test]
    fn test_wrong_root_trust_key_fails() {
        let root_kp = create_test_root_trust();
        let wrong_root_kp = create_test_root_trust();
        let tee_kp = PqcSigningKeypair::generate().unwrap();
        let tee_id = TeeId::new([1u8; 32]);
        let code_hash = B256::from([2u8; 32]);

        let cert = create_test_certificate(&root_kp, &tee_kp, tee_id, code_hash);
        let evidence = create_test_evidence(&tee_kp, cert, tee_id, code_hash);

        let verifier = AttestationVerifier::new(
            wrong_root_kp.public_key_bytes().to_vec(),
            TeeMode::Simulator,
        );

        let result = verifier.verify(&evidence).unwrap();
        assert_eq!(result, AttestationResult::InvalidRootTrust);
    }

    #[test]
    fn test_simulator_rejected_in_production() {
        let root_kp = create_test_root_trust();
        let tee_kp = PqcSigningKeypair::generate().unwrap();
        let tee_id = TeeId::new([1u8; 32]);
        let code_hash = B256::from([2u8; 32]);

        let cert = create_test_certificate(&root_kp, &tee_kp, tee_id, code_hash);
        let evidence = create_test_evidence(&tee_kp, cert, tee_id, code_hash);

        let verifier = AttestationVerifier::new(
            root_kp.public_key_bytes().to_vec(),
            TeeMode::Production,
        );

        let result = verifier.verify(&evidence).unwrap();
        assert!(!result.is_acceptable(false));
    }
}
