//! TEE-4: Ethereum Mainnet Validator
//!
//! Runs an Ethereum consensus validator inside a TEE enclave.
//! Manages the LiquidStaking contract lifecycle:
//! - Monitors deposits and creates validators when ≥32 ETH buffered
//! - Performs attestation/proposal duties on behalf of stakers
//! - Reports staking rewards (5% treasury, 95% pool)
//! - After continuous uptime, the TEE operator can mine a block on the TEE-chain

pub mod validator;
pub mod staking_pool;

use tee_crypto::*;
use tee_types::*;
use alloy_primitives::{Address, B256, U256};

use validator::{ValidatorNode, ValidatorStatus, ValidatorConfig};
use staking_pool::{StakingPool, PoolConfig};

/// TEE-4 Ethereum Validator Coordinator.
pub struct EthValidatorTee {
    // ── Identity ──
    keypair: PqcSigningKeypair,
    tee_id: TeeId,
    code_hash: B256,
    certificate: RootTrustCertificate,

    // ── Validator ──
    validator: ValidatorNode,
    pool: StakingPool,

    // ── Mining ──
    round_id: u64,
    blocks_produced: u64,
    operator: Address,
    max_reward: U256,

    // ── Uptime tracking ──
    started_at: u64,
    total_attestations: u64,
    total_proposals: u64,
    missed_attestations: u64,
    uptime_threshold_secs: u64,
}

impl EthValidatorTee {
    pub fn new(
        keypair: PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
        certificate: RootTrustCertificate,
        validator_config: ValidatorConfig,
        pool_config: PoolConfig,
        operator: Address,
        max_reward: U256,
        uptime_threshold_secs: u64,
    ) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            keypair, tee_id, code_hash, certificate,
            validator: ValidatorNode::new(validator_config),
            pool: StakingPool::new(pool_config),
            round_id: 0, blocks_produced: 0, operator, max_reward,
            started_at: now, total_attestations: 0, total_proposals: 0,
            missed_attestations: 0, uptime_threshold_secs,
        }
    }

    /// Process an ETH deposit into the pool.
    pub fn deposit(&mut self, depositor: Address, amount: U256) -> U256 {
        self.pool.deposit(depositor, amount)
    }

    /// Try to create validators from buffered ETH.
    pub fn create_validators(&mut self) -> u32 {
        let mut created = 0;
        while self.pool.can_create_validator() {
            self.pool.create_validator();
            self.validator.add_validator();
            created += 1;
        }
        created
    }

    /// Simulate one epoch of validator duties (attestations + proposals).
    pub fn process_epoch(&mut self, epoch: u64) -> EpochResult {
        let active = self.validator.active_count();
        if active == 0 {
            return EpochResult { attestations: 0, proposals: 0, missed: 0, rewards_eth: U256::ZERO };
        }

        // Each validator attests once per epoch, ~1 proposal per 32 epochs
        let attestations = active;
        let proposals = if epoch % 32 == 0 { 1 } else { 0 };
        let missed = if epoch % 100 == 99 { 1 } else { 0 }; // simulate rare miss

        self.total_attestations += attestations as u64;
        self.total_proposals += proposals as u64;
        self.missed_attestations += missed as u64;

        // Rewards: ~0.0025 ETH per validator per epoch (simplified)
        let reward_per_validator = U256::from(2_500_000_000_000_000u128); // 0.0025 ETH
        let total_rewards = reward_per_validator * U256::from(active);

        // Report rewards to pool (handles 5% treasury split)
        self.pool.report_rewards(total_rewards);
        self.validator.record_epoch(epoch);

        EpochResult {
            attestations: attestations as u64,
            proposals: proposals as u64,
            missed: missed as u64,
            rewards_eth: total_rewards,
        }
    }

    /// Check if operator qualifies to mine (sufficient uptime).
    pub fn can_mine(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        let uptime = now.saturating_sub(self.started_at);
        let has_uptime = uptime >= self.uptime_threshold_secs;
        let has_validators = self.validator.active_count() > 0;
        let good_performance = self.attestation_rate() >= 0.95;
        has_uptime && has_validators && good_performance
    }

    /// Attestation success rate (0.0 - 1.0).
    pub fn attestation_rate(&self) -> f64 {
        if self.total_attestations == 0 { return 1.0; }
        1.0 - (self.missed_attestations as f64 / (self.total_attestations + self.missed_attestations) as f64)
    }

    /// Uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.started_at)
    }

    /// Produce a block on the TEE-chain.
    pub fn produce_block(&mut self, parent_hash: B256) -> Result<SignedRoundComplete, Box<dyn std::error::Error>> {
        self.round_id += 1;

        let tee_data = serde_json::to_vec(&serde_json::json!({
            "tee": "TEE-4 ETH Validator",
            "active_validators": self.validator.active_count(),
            "total_attestations": self.total_attestations,
            "total_proposals": self.total_proposals,
            "missed_attestations": self.missed_attestations,
            "attestation_rate": format!("{:.2}%", self.attestation_rate() * 100.0),
            "total_pooled_eth": self.pool.total_pooled_eth().to_string(),
            "total_rewards_eth": self.pool.total_rewards().to_string(),
            "treasury_fees": self.pool.treasury_fees().to_string(),
            "exchange_rate": self.pool.exchange_rate_display(),
            "stakers": self.pool.staker_count(),
        }))?;

        let msg = RoundCompleteMessage {
            tee_id: self.tee_id, round_id: self.round_id,
            parent_block_hash: parent_hash, payments: vec![],
            incentives: vec![PaymentInstruction {
                recipient: self.operator, amount: self.max_reward, is_reward: true,
            }],
            timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: tee_data, transaction_hashes: vec![],
        };

        let sig = sign_message(&self.keypair, &msg.to_signing_bytes())?;

        let mut evidence = AttestationEvidence {
            tee_id: self.tee_id, enclave_measurement: self.code_hash,
            root_trust_cert: self.certificate.clone(),
            platform_data: PlatformData::Simulator {
                report: vec![0u8; 64], simulator_version: "4.0.0".to_string(),
            },
            nonce: B256::random(), timestamp: chrono::Utc::now().timestamp() as u64,
            self_signature: vec![],
        };
        evidence.self_signature = sign_message(&self.keypair, &evidence.to_signing_bytes())?;

        self.blocks_produced += 1;

        Ok(SignedRoundComplete {
            message: msg, signature: sig,
            attestation_evidence: bincode::serialize(&evidence)?,
        })
    }
}

pub struct EpochResult {
    pub attestations: u64,
    pub proposals: u64,
    pub missed: u64,
    pub rewards_eth: U256,
}

// ════════════════════════════════════════════════════════════════
// Simulator
// ════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  TEE-4: Ethereum Mainnet Validator (Liquid Staking)      ║");
    println!("║  teeETH Receipt Tokens · 5% Treasury · Usage Mining     ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // ── Phase 1: Initialize ──
    println!("━━━ Phase 1: TEE Initialization ━━━\n");
    let keypair = PqcSigningKeypair::generate()?;
    let tee_id = TeeId::new({
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new(); h.update(b"tee4-eth-validator");
        let mut a = [0u8;32]; a.copy_from_slice(&h.finalize()); a
    });

    let cert = RootTrustCertificate {
        version: 1, subject_tee_id: tee_id, subject_code_hash: B256::from([0xEE;32]),
        subject_public_key: keypair.public_key_bytes().to_vec(),
        issued_at: chrono::Utc::now().timestamp() as u64, expires_at: 0,
        root_trust_signature: vec![0u8;100],
    };

    let operator = Address::from([0xBB;20]);
    let treasury = Address::from([0xCC;20]);
    let mut tee = EthValidatorTee::new(
        keypair, tee_id, B256::from([0xEE;32]), cert,
        ValidatorConfig::test_mode(),
        PoolConfig { treasury, treasury_fee_bps: 500 },
        operator,
        U256::from(25_000_000_000_000_000_000u128), // 25 TEEC per block
        0, // 0 uptime threshold for testing
    );

    println!("  Operator:  {}", operator);
    println!("  Treasury:  {}", treasury);
    println!("  Mode:      Test (0s uptime threshold)\n");

    // ── Phase 2: Deposits ──
    println!("━━━ Phase 2: ETH Deposits ━━━\n");
    let alice = Address::from([0xA1;20]);
    let bob = Address::from([0xB0;20]);

    let shares_a = tee.deposit(alice, U256::from(50_000_000_000_000_000_000u128)); // 50 ETH
    println!("  Alice deposits 50 ETH → {} teeETH", shares_a);

    let shares_b = tee.deposit(bob, U256::from(30_000_000_000_000_000_000u128)); // 30 ETH
    println!("  Bob deposits 30 ETH → {} teeETH", shares_b);

    println!("  Pool: {} ETH total, {} buffered", tee.pool.total_pooled_eth(), tee.pool.buffered());
    println!("  Pending validators: {}\n", tee.pool.pending_validators());

    // ── Phase 3: Create Validators ──
    println!("━━━ Phase 3: Validator Creation ━━━\n");
    let created = tee.create_validators();
    println!("  Created {} validators (each 32 ETH)", created);
    println!("  Active: {}, Remaining buffer: {} ETH\n", tee.validator.active_count(), tee.pool.buffered());

    // ── Phase 4: Epochs + Rewards ──
    println!("━━━ Phase 4: Validator Epochs ━━━\n");
    for epoch in 0..5 {
        let result = tee.process_epoch(epoch);
        println!("  Epoch {} | atts={}, props={}, missed={} | rewards={} wei | rate={}",
            epoch, result.attestations, result.proposals, result.missed,
            result.rewards_eth, tee.pool.exchange_rate_display());
    }
    println!("\n  Total rewards: {} wei", tee.pool.total_rewards());
    println!("  Treasury fees: {} wei", tee.pool.treasury_fees());
    println!("  Attestation rate: {:.2}%\n", tee.attestation_rate() * 100.0);

    // ── Phase 5: Mine Block ──
    println!("━━━ Phase 5: TEE-Chain Block Production ━━━\n");
    if tee.can_mine() {
        let block = tee.produce_block(B256::ZERO)?;
        let data: serde_json::Value = serde_json::from_slice(&block.message.tee_specific_data)?;
        println!("  ✓ Block produced:");
        println!("    Round:       {}", block.message.round_id);
        println!("    Validators:  {}", data["active_validators"]);
        println!("    Attestations:{}", data["total_attestations"]);
        println!("    Att. rate:   {}", data["attestation_rate"]);
        println!("    Pooled ETH:  {}", data["total_pooled_eth"]);
        println!("    Rewards:     {}", data["total_rewards_eth"]);
        println!("    Treasury:    {}", data["treasury_fees"]);
        println!("    Exchange:    {}", data["exchange_rate"]);
        println!("    Reward:      {} TEEC → {}", 25, operator);
    } else {
        println!("  ✗ Cannot mine yet (uptime or performance insufficient)");
    }

    println!();
    Ok(())
}
