//! TEE Consensus Engine.
//!
//! Validates blocks by verifying that each block's extra-data contains
//! a valid TEE-signed RoundCompleteMessage with attestation evidence
//! chaining back to the Root Trust TEE.

use alloy_primitives::B256;
use tee_attestation::AttestationVerifier;
use tee_crypto::{verify_round_complete, verify_signature};
use tee_types::{AttestationEvidence, AttestationResult, SignedRoundComplete, TeeMode, TeeRole};
use thiserror::Error;

use crate::TeeRegistry;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Block missing TEE signature in extra-data")]
    MissingTeeSignature,
    #[error("Failed to decode TEE round-complete message: {0}")]
    DecodeError(String),
    #[error("TEE {0} is not registered")]
    UnregisteredTee(String),
    #[error("TEE {0} is not eligible for mining")]
    NotMiningEligible(String),
    #[error("Root Trust TEE cannot produce blocks")]
    RootTrustCannotMine,
    #[error("TEE signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Attestation verification failed: {0}")]
    InvalidAttestation(String),
    #[error("Round ID {0} is not monotonically increasing (expected > {1})")]
    InvalidRoundId(u64, u64),
    #[error("Parent block hash mismatch")]
    ParentHashMismatch,
    #[error("Block reward exceeds maximum for TEE: {0}")]
    RewardExceedsMax(String),
    #[error("Registry error: {0}")]
    RegistryError(#[from] crate::RegistryError),
}

/// The TEE consensus engine that validates blocks.
pub struct TeeConsensusEngine {
    /// Attestation verifier for the trust chain.
    attestation_verifier: AttestationVerifier,
    /// Local TEE registry.
    registry: TeeRegistry,
    /// TEE execution mode.
    tee_mode: TeeMode,
    /// Last known round IDs per TEE for monotonicity checks.
    last_round_ids: std::collections::HashMap<tee_types::TeeId, u64>,
}

impl TeeConsensusEngine {
    /// Create a new consensus engine.
    pub fn new(
        root_trust_public_key: Vec<u8>,
        registry: TeeRegistry,
        tee_mode: TeeMode,
    ) -> Self {
        Self {
            attestation_verifier: AttestationVerifier::new(root_trust_public_key, tee_mode),
            registry,
            tee_mode,
            last_round_ids: std::collections::HashMap::new(),
        }
    }

    /// Validate a block's TEE consensus proof.
    ///
    /// This is called for every block during validation. The extra-data
    /// field of the block header must contain a serialized `SignedRoundComplete`.
    pub fn validate_block(
        &mut self,
        extra_data: &[u8],
        parent_hash: B256,
    ) -> Result<SignedRoundComplete, ConsensusError> {
        // Step 1: Decode the signed round-complete message from extra-data
        let signed_rc = SignedRoundComplete::from_bytes(extra_data)
            .map_err(|e| ConsensusError::DecodeError(e.to_string()))?;

        let tee_id = signed_rc.message.tee_id;

        // Step 2: Check TEE is registered and eligible
        self.registry.can_produce_block(&tee_id)?;

        let registration = self.registry.get(&tee_id)
            .ok_or_else(|| ConsensusError::UnregisteredTee(tee_id.to_string()))?;

        // Step 3: Verify Root Trust TEE cannot mine
        if registration.role == TeeRole::RootTrust {
            return Err(ConsensusError::RootTrustCannotMine);
        }

        // Step 4: Verify parent hash matches
        if signed_rc.message.parent_block_hash != parent_hash {
            return Err(ConsensusError::ParentHashMismatch);
        }

        // Step 5: Verify round ID is monotonically increasing
        if let Some(&last_round) = self.last_round_ids.get(&tee_id) {
            if signed_rc.message.round_id <= last_round {
                return Err(ConsensusError::InvalidRoundId(
                    signed_rc.message.round_id,
                    last_round,
                ));
            }
        }

        // Step 6: Verify the ML-DSA signature
        let public_key = self.registry.get_public_key(&tee_id)
            .ok_or_else(|| ConsensusError::UnregisteredTee(tee_id.to_string()))?;

        let sig_valid = verify_round_complete(
            public_key,
            &signed_rc.message,
            &signed_rc.signature,
        )
        .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;

        if !sig_valid {
            return Err(ConsensusError::InvalidSignature(
                "ML-DSA signature verification returned false".to_string(),
            ));
        }

        // Step 7: Verify attestation evidence
        let attestation_evidence: AttestationEvidence = bincode::deserialize(&signed_rc.attestation_evidence)
            .map_err(|e| ConsensusError::InvalidAttestation(format!("Failed to decode attestation: {e}")))?;

        let attestation_result = self.attestation_verifier.verify(&attestation_evidence)
            .map_err(|e| ConsensusError::InvalidAttestation(e.to_string()))?;

        let allow_sim = self.tee_mode == TeeMode::Simulator;
        if !attestation_result.is_acceptable(allow_sim) {
            return Err(ConsensusError::InvalidAttestation(
                format!("Attestation result: {:?}", attestation_result),
            ));
        }

        // Step 8: Verify reward caps (individual AND total)
        let max_reward = registration.config.max_reward_per_block;
        let mut total_incentive = alloy_primitives::U256::ZERO;
        for incentive in &signed_rc.message.incentives {
            if incentive.amount > max_reward {
                return Err(ConsensusError::RewardExceedsMax(
                    format!("Incentive {} exceeds max {}", incentive.amount, max_reward),
                ));
            }
            total_incentive = total_incentive.checked_add(incentive.amount)
                .ok_or_else(|| ConsensusError::RewardExceedsMax(
                    "Total incentive amount overflow".to_string(),
                ))?;
        }
        // SECURITY: Cap the sum of ALL incentives, not just individual ones
        if total_incentive > max_reward {
            return Err(ConsensusError::RewardExceedsMax(
                format!("Total incentives {} exceed max {}", total_incentive, max_reward),
            ));
        }

        // Update last round ID
        self.last_round_ids.insert(tee_id, signed_rc.message.round_id);

        tracing::info!(
            %tee_id,
            round_id = signed_rc.message.round_id,
            "Block validated by TEE consensus"
        );

        Ok(signed_rc)
    }

    /// Get a reference to the TEE registry.
    pub fn registry(&self) -> &TeeRegistry {
        &self.registry
    }

    /// Get a mutable reference to the TEE registry.
    pub fn registry_mut(&mut self) -> &mut TeeRegistry {
        &mut self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use tee_crypto::{PqcSigningKeypair, sign_message, sign_round_complete};
    use tee_types::*;

    fn setup_test_env() -> (PqcSigningKeypair, PqcSigningKeypair, TeeId, B256, TeeRegistry) {
        let root_kp = PqcSigningKeypair::generate().unwrap();
        let tee_kp = PqcSigningKeypair::generate().unwrap();
        let tee_id = TeeId::new([1u8; 32]);
        let code_hash = B256::from([2u8; 32]);

        let mut registry = TeeRegistry::new();
        registry.register(TeeRegistration {
            tee_id,
            code_hash,
            pqc_public_key: tee_kp.public_key_bytes().to_vec(),
            root_trust_certificate: vec![],
            role: TeeRole::BlockCoordinator,
            status: TeeStatus::Active,
            operator: Address::ZERO,
            config: TeeConfig {
                name: "Test TEE".to_string(),
                description: "Test".to_string(),
                api_endpoints: vec![],
                max_reward_per_block: U256::from(1000),
                mining_eligible: true,
                custom_params: vec![],
            },
            registered_at_block: 0,
        });

        (root_kp, tee_kp, tee_id, code_hash, registry)
    }

    fn create_signed_round_complete(
        root_kp: &PqcSigningKeypair,
        tee_kp: &PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
        round_id: u64,
        parent_hash: B256,
    ) -> SignedRoundComplete {
        let msg = RoundCompleteMessage {
            tee_id,
            round_id,
            parent_block_hash: parent_hash,
            payments: vec![],
            incentives: vec![],
            timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: vec![],
            transaction_hashes: vec![],
        };

        let signature = sign_round_complete(tee_kp, &msg).unwrap();

        // Create attestation evidence
        let mut cert = RootTrustCertificate {
            version: 1,
            subject_tee_id: tee_id,
            subject_code_hash: code_hash,
            subject_public_key: tee_kp.public_key_bytes().to_vec(),
            issued_at: chrono::Utc::now().timestamp() as u64,
            expires_at: 0,
            root_trust_signature: vec![],
        };
        cert.root_trust_signature = sign_message(root_kp, &cert.to_signing_bytes()).unwrap();

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
        evidence.self_signature = sign_message(tee_kp, &evidence.to_signing_bytes()).unwrap();

        SignedRoundComplete {
            message: msg,
            signature,
            attestation_evidence: bincode::serialize(&evidence).unwrap(),
        }
    }

    #[test]
    fn test_valid_block() {
        let (root_kp, tee_kp, tee_id, code_hash, registry) = setup_test_env();
        let parent_hash = B256::ZERO;

        let mut engine = TeeConsensusEngine::new(
            root_kp.public_key_bytes().to_vec(),
            registry,
            TeeMode::Simulator,
        );

        let signed_rc = create_signed_round_complete(
            &root_kp, &tee_kp, tee_id, code_hash, 1, parent_hash,
        );

        let result = engine.validate_block(&signed_rc.to_bytes(), parent_hash);
        assert!(result.is_ok(), "Valid block should pass consensus: {:?}", result.err());
    }

    #[test]
    fn test_monotonic_round_id() {
        let (root_kp, tee_kp, tee_id, code_hash, registry) = setup_test_env();
        let parent_hash = B256::ZERO;

        let mut engine = TeeConsensusEngine::new(
            root_kp.public_key_bytes().to_vec(),
            registry,
            TeeMode::Simulator,
        );

        // First block with round_id=1
        let signed_rc1 = create_signed_round_complete(
            &root_kp, &tee_kp, tee_id, code_hash, 1, parent_hash,
        );
        engine.validate_block(&signed_rc1.to_bytes(), parent_hash).unwrap();

        // Second block with round_id=1 should fail (not monotonically increasing)
        let signed_rc2 = create_signed_round_complete(
            &root_kp, &tee_kp, tee_id, code_hash, 1, parent_hash,
        );
        let result = engine.validate_block(&signed_rc2.to_bytes(), parent_hash);
        assert!(matches!(result, Err(ConsensusError::InvalidRoundId(_, _))));
    }
}
