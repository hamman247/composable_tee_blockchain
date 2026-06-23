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
    #[error("Block produced too fast: {elapsed_secs}s since last block, minimum is {min_secs}s")]
    BlockTooFast { elapsed_secs: u64, min_secs: u64 },
    #[error("TEE {0} has not been active long enough to mine (first seen {1}s ago, need {2}s)")]
    InsufficientUptime(String, u64, u64),
    #[error("TEE {0} is in warmup cooldown after reconnection ({1}s remaining)")]
    WarmupCooldown(String, u64),
    #[error("Not this TEE's turn to produce a block (expected {expected}, got {got})")]
    NotYourTurn { expected: String, got: String },
    #[error("Block omits {count} stale transactions (oldest pending for {stale_blocks} blocks)")]
    StaleTransactionsOmitted { count: usize, stale_blocks: u64 },
    #[error("TEE-3 service rate too low: {rate:.1}% (minimum {min:.1}%)")]
    ServiceRateTooLow { rate: f64, min: f64 },
    #[error("TEE-2 block missing checkpoint hash in tee_specific_data")]
    MissingCheckpointHash,
    #[error("Registry error: {0}")]
    RegistryError(#[from] crate::RegistryError),
}

/// Rate-limiting configuration for block production.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Minimum seconds between blocks from the same TEE.
    /// Production: 12-30s depending on role. Test: 0 to disable.
    pub min_block_interval_secs: u64,
    /// Minimum seconds a TEE must be observed before it can mine.
    /// Prevents uptime self-reporting cheats.
    pub min_first_seen_secs: u64,
    /// Seconds of inactivity before a TEE is considered "reconnecting"
    /// and must go through a warmup period.
    pub inactivity_threshold_secs: u64,
    /// Warmup period (seconds) after reconnection before mining resumes.
    pub warmup_period_secs: u64,
}

impl RateLimitConfig {
    /// Production defaults — strict rate limiting.
    pub fn production() -> Self {
        Self {
            min_block_interval_secs: 12,
            min_first_seen_secs: 300,      // 5 minutes
            inactivity_threshold_secs: 600, // 10 minutes
            warmup_period_secs: 120,        // 2 minutes
        }
    }

    /// Test defaults — relaxed for local testnet.
    pub fn test() -> Self {
        Self {
            min_block_interval_secs: 2,
            min_first_seen_secs: 5,
            inactivity_threshold_secs: 30,
            warmup_period_secs: 3,
        }
    }

    /// Disabled — no rate limiting (for unit tests).
    pub fn disabled() -> Self {
        Self {
            min_block_interval_secs: 0,
            min_first_seen_secs: 0,
            inactivity_threshold_secs: u64::MAX,
            warmup_period_secs: 0,
        }
    }
}

/// Fairness configuration for anti-censorship and anti-monopolization.
#[derive(Debug, Clone)]
pub struct FairnessConfig {
    /// If true, enforce round-robin for BlockCoordinator TEEs.
    pub enforce_coordinator_rotation: bool,
    /// Maximum blocks a transaction can be pending before forced inclusion.
    /// After this many blocks, any TEE-1 block MUST include the stale transaction.
    pub max_stale_tx_blocks: u64,
    /// Minimum service response rate for TEE-3 to mine (0.0 - 1.0).
    /// e.g. 0.95 means at least 95% of queries must be served.
    pub min_tee3_service_rate: f64,
    /// Whether to require checkpoint hashes in TEE-2 blocks.
    pub require_tee2_checkpoint: bool,
    /// SECURITY [D1]: Maximum pending transaction pool size.
    /// Prevents memory exhaustion from tx spam.
    pub max_pending_pool_size: usize,
}

impl FairnessConfig {
    pub fn production() -> Self {
        Self {
            enforce_coordinator_rotation: true,
            max_stale_tx_blocks: 10,
            min_tee3_service_rate: 0.90,
            require_tee2_checkpoint: true,
            max_pending_pool_size: 10_000,
        }
    }
    pub fn test() -> Self {
        Self {
            enforce_coordinator_rotation: true,
            max_stale_tx_blocks: 5,
            min_tee3_service_rate: 0.80,
            require_tee2_checkpoint: true,
            max_pending_pool_size: 1_000,
        }
    }
    pub fn disabled() -> Self {
        Self {
            enforce_coordinator_rotation: false,
            max_stale_tx_blocks: u64::MAX,
            min_tee3_service_rate: 0.0,
            require_tee2_checkpoint: false,
            max_pending_pool_size: 100_000,
        }
    }
}

/// Tracks a pending transaction for forced inclusion enforcement.
#[derive(Debug, Clone)]
struct PendingTx {
    tx_hash: B256,
    first_seen_block: u64,
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
    /// SECURITY [V1]: Last block timestamp per TEE for rate limiting.
    last_block_timestamps: std::collections::HashMap<tee_types::TeeId, u64>,
    /// SECURITY [V2]: First-seen timestamp per TEE (consensus-tracked, not self-reported).
    first_seen_timestamps: std::collections::HashMap<tee_types::TeeId, u64>,
    /// Rate-limiting configuration.
    rate_limit: RateLimitConfig,
    /// SECURITY [M1]: Fairness configuration.
    fairness: FairnessConfig,
    /// SECURITY [M1]: Current block height for forced inclusion tracking.
    block_height: u64,
    /// SECURITY [M1]: Pending transactions awaiting inclusion.
    pending_txs: Vec<PendingTx>,
    /// SECURITY [C1]: TEE-3 service metrics — windowed per epoch.
    /// (queries_served_this_epoch, queries_received_this_epoch, epoch_start_ts)
    tee3_service_metrics: std::collections::HashMap<tee_types::TeeId, (u64, u64, u64)>,
}

impl TeeConsensusEngine {
    /// Create a new consensus engine with default rate limiting for the mode.
    pub fn new(
        root_trust_public_key: Vec<u8>,
        registry: TeeRegistry,
        tee_mode: TeeMode,
    ) -> Self {
        // Default: disabled for backward compatibility with existing tests
        Self::with_config(
            root_trust_public_key, registry, tee_mode,
            RateLimitConfig::disabled(), FairnessConfig::disabled(),
        )
    }

    /// Create a new consensus engine with explicit rate limiting config.
    pub fn with_rate_limit(
        root_trust_public_key: Vec<u8>,
        registry: TeeRegistry,
        tee_mode: TeeMode,
        rate_limit: RateLimitConfig,
    ) -> Self {
        Self::with_config(
            root_trust_public_key, registry, tee_mode,
            rate_limit, FairnessConfig::disabled(),
        )
    }

    /// Create a new consensus engine with full configuration.
    pub fn with_config(
        root_trust_public_key: Vec<u8>,
        registry: TeeRegistry,
        tee_mode: TeeMode,
        rate_limit: RateLimitConfig,
        fairness: FairnessConfig,
    ) -> Self {
        Self {
            attestation_verifier: AttestationVerifier::new(root_trust_public_key.clone(), tee_mode),
            registry,
            tee_mode,
            last_round_ids: std::collections::HashMap::new(),
            last_block_timestamps: std::collections::HashMap::new(),
            first_seen_timestamps: std::collections::HashMap::new(),
            rate_limit,
            fairness,
            block_height: 0,
            pending_txs: Vec::new(),
            tee3_service_metrics: std::collections::HashMap::new(),
        }
    }

    /// Submit a transaction to the pending pool for forced-inclusion tracking.
    /// SECURITY [D1]: Capped at max_pending_pool_size to prevent memory exhaustion.
    pub fn submit_transaction(&mut self, tx_hash: B256) {
        // Don't accept duplicates
        if self.pending_txs.iter().any(|p| p.tx_hash == tx_hash) {
            return;
        }
        // SECURITY [D1]: Enforce pool size cap — drop oldest if full
        if self.pending_txs.len() >= self.fairness.max_pending_pool_size {
            // Prune the oldest 10% to make room
            let prune_count = self.fairness.max_pending_pool_size / 10;
            self.pending_txs.drain(..prune_count.min(self.pending_txs.len()));
            tracing::warn!(
                pruned = prune_count,
                pool_size = self.pending_txs.len(),
                "Pending tx pool full — pruned oldest entries"
            );
        }
        self.pending_txs.push(PendingTx {
            tx_hash,
            first_seen_block: self.block_height,
        });
    }

    /// SECURITY [D1]: Prune very old pending transactions that are likely invalid.
    /// Called periodically to prevent unbounded accumulation.
    pub fn prune_stale_pending(&mut self) {
        let max_age = self.fairness.max_stale_tx_blocks * 2;
        let current_height = self.block_height;
        let before = self.pending_txs.len();
        self.pending_txs.retain(|p| {
            current_height.saturating_sub(p.first_seen_block) < max_age
        });
        let pruned = before - self.pending_txs.len();
        if pruned > 0 {
            tracing::info!(pruned, remaining = self.pending_txs.len(), "Pruned stale pending txs");
        }
    }

    /// Report TEE-3 service metrics (called by the TEE-3 node).
    /// SECURITY [D2]: Uses windowed counters that reset each epoch to prevent overflow.
    pub fn report_tee3_service(
        &mut self,
        tee_id: tee_types::TeeId,
        queries_served: u64,
        queries_received: u64,
    ) {
        let now = chrono::Utc::now().timestamp() as u64;
        let entry = self.tee3_service_metrics.entry(tee_id).or_insert((0, 0, now));
        // Reset epoch every hour
        if now.saturating_sub(entry.2) >= 3600 {
            *entry = (queries_served, queries_received, now);
        } else {
            entry.0 += queries_served;
            entry.1 += queries_received;
        }
    }

    /// Get the TEE-3 service rate for a given TEE.
    pub fn tee3_service_rate(&self, tee_id: &tee_types::TeeId) -> f64 {
        match self.tee3_service_metrics.get(tee_id) {
            Some(&(served, received, _)) if received > 0 => served as f64 / received as f64,
            _ => 1.0, // No data yet — assume good
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
            .ok_or_else(|| ConsensusError::UnregisteredTee(tee_id.to_string()))?
            .clone();

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

        // SECURITY [V1]: Step 5b — Enforce minimum block interval per TEE.
        let block_ts = signed_rc.message.timestamp;
        if self.rate_limit.min_block_interval_secs > 0 {
            if let Some(&last_ts) = self.last_block_timestamps.get(&tee_id) {
                let elapsed = block_ts.saturating_sub(last_ts);
                if elapsed < self.rate_limit.min_block_interval_secs {
                    return Err(ConsensusError::BlockTooFast {
                        elapsed_secs: elapsed,
                        min_secs: self.rate_limit.min_block_interval_secs,
                    });
                }
            }
        }

        // SECURITY [V2]: Step 5c — Track first-seen and enforce minimum uptime.
        if !self.first_seen_timestamps.contains_key(&tee_id) {
            self.first_seen_timestamps.insert(tee_id, block_ts);
        }
        if self.rate_limit.min_first_seen_secs > 0 {
            let first_seen = self.first_seen_timestamps[&tee_id];
            let time_active = block_ts.saturating_sub(first_seen);
            if time_active < self.rate_limit.min_first_seen_secs {
                return Err(ConsensusError::InsufficientUptime(
                    tee_id.to_string(),
                    time_active,
                    self.rate_limit.min_first_seen_secs,
                ));
            }
        }

        // SECURITY [V4]: Step 5d — Warmup cooldown after reconnection.
        if self.rate_limit.warmup_period_secs > 0 {
            if let Some(&last_ts) = self.last_block_timestamps.get(&tee_id) {
                let gap = block_ts.saturating_sub(last_ts);
                if gap >= self.rate_limit.inactivity_threshold_secs {
                    // TEE was inactive for too long — treat as reconnection.
                    // Reset first-seen to now and require warmup.
                    self.first_seen_timestamps.insert(tee_id, block_ts);
                    return Err(ConsensusError::WarmupCooldown(
                        tee_id.to_string(),
                        self.rate_limit.warmup_period_secs,
                    ));
                }
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

        // ── SECURITY [M1]: Step 9 — Enforce round-robin for BlockCoordinator TEEs ──
        if self.fairness.enforce_coordinator_rotation
            && registration.role == TeeRole::BlockCoordinator
        {
            if let Some(expected_id) = self.registry.peek_next_block_producer() {
                if tee_id != expected_id {
                    return Err(ConsensusError::NotYourTurn {
                        expected: expected_id.to_string(),
                        got: tee_id.to_string(),
                    });
                }
            }
        }

        // ── SECURITY [M1]: Step 10 — Forced transaction inclusion ──
        if registration.role == TeeRole::BlockCoordinator {
            let stale_count = self.pending_txs.iter()
                .filter(|p| self.block_height.saturating_sub(p.first_seen_block) >= self.fairness.max_stale_tx_blocks)
                .count();
            let included: std::collections::HashSet<_> = signed_rc.message.transaction_hashes.iter().collect();
            let stale_not_included = self.pending_txs.iter()
                .filter(|p| {
                    self.block_height.saturating_sub(p.first_seen_block) >= self.fairness.max_stale_tx_blocks
                        && !included.contains(&p.tx_hash)
                })
                .count();
            if stale_not_included > 0 && stale_count > 0 {
                let oldest = self.pending_txs.iter()
                    .map(|p| self.block_height.saturating_sub(p.first_seen_block))
                    .max()
                    .unwrap_or(0);
                return Err(ConsensusError::StaleTransactionsOmitted {
                    count: stale_not_included,
                    stale_blocks: oldest,
                });
            }
            // Remove included transactions from pending pool
            self.pending_txs.retain(|p| !included.contains(&p.tx_hash));
        }

        // ── SECURITY [C1]: Step 11 — TEE-3 service level verification ──
        if registration.role == TeeRole::OllamaInference
            && self.fairness.min_tee3_service_rate > 0.0
        {
            let rate = self.tee3_service_rate(&tee_id);
            if rate < self.fairness.min_tee3_service_rate {
                return Err(ConsensusError::ServiceRateTooLow {
                    rate: rate * 100.0,
                    min: self.fairness.min_tee3_service_rate * 100.0,
                });
            }
        }

        // ── SECURITY [M2]: Step 12 — TEE-2 must include checkpoint hash ──
        if registration.role == TeeRole::AiTraining
            && self.fairness.require_tee2_checkpoint
            && !signed_rc.message.tee_specific_data.is_empty()
        {
            // Parse tee_specific_data as JSON and verify a checkpoint_hash field exists
            if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&signed_rc.message.tee_specific_data) {
                if data.get("checkpoint_hash").is_none() {
                    return Err(ConsensusError::MissingCheckpointHash);
                }
            } else {
                return Err(ConsensusError::MissingCheckpointHash);
            }
        }

        // Update tracking state
        self.last_round_ids.insert(tee_id, signed_rc.message.round_id);
        self.last_block_timestamps.insert(tee_id, block_ts);
        self.block_height += 1;

        // SECURITY [D1]: Auto-prune very old pending transactions every 100 blocks
        if self.block_height % 100 == 0 {
            self.prune_stale_pending();
        }

        // Advance round-robin if this was a coordinator block
        if registration.role == TeeRole::BlockCoordinator {
            self.registry.next_block_producer();
        }

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
