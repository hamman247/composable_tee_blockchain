//! TEE-3: Ollama Inference Service
//!
//! Runs an Ollama model with open endpoints, gated by EVM wallet signatures.
//!
//! ## Flow
//! 1. User signs query with their EVM wallet (EIP-191 personal_sign)
//! 2. TEE verifies the ECDSA signature → recovers signer address
//! 3. TEE checks that the signer has staked ≥100 TEEC on-chain
//! 4. TEE forwards query to local Ollama instance
//! 5. TEE tracks usage (queries, tokens, per-user)
//! 6. After ≥1000 queries or ≥500K tokens, the operator can mine a block
//!
//! ## Security
//! - All signature verification happens inside the TEE enclave
//! - The Ollama API is only accessible through the TEE (not directly)
//! - Usage metrics are measured by the TEE, not self-reported

pub mod signature;
pub mod staking;
pub mod usage;
pub mod ollama;

use tee_crypto::{PqcSigningKeypair, sign_message};
use tee_types::*;
use alloy_primitives::{Address, B256, U256};
use std::collections::HashMap;

use signature::{SignedQuery, SignatureVerifier, VerifiedQuery, SignatureError};
use staking::{StakingRegistry, StakingError, RateLimiter};
use usage::{UsageTracker, UsageRecord, UsageSummary, MiningThreshold};
use ollama::{OllamaClient, OllamaConfig};

/// TEE-3 Ollama Inference Coordinator.
pub struct OllamaInferenceTee {
    // ── Identity ──
    keypair: PqcSigningKeypair,
    tee_id: TeeId,
    code_hash: B256,
    certificate: RootTrustCertificate,

    // ── Verification ──
    sig_verifier: SignatureVerifier,
    staking: StakingRegistry,
    rate_limiter: RateLimiter,

    // ── Ollama ──
    ollama: OllamaClient,

    // ── Usage & Mining ──
    usage: UsageTracker,
    round_id: u64,
    blocks_produced: u64,
    max_reward: U256,
    operator: Address,

    // ── Stats ──
    total_queries_all_time: u64,
    total_rejections: u64,
}

/// Result of processing a signed query.
#[derive(Debug)]
pub enum QueryResult {
    /// Query was served successfully.
    Success {
        response: String,
        tokens_in: u32,
        tokens_out: u32,
        latency_ms: u64,
        signer: Address,
    },
    /// Query was rejected.
    Rejected(QueryRejection),
}

/// Why a query was rejected.
#[derive(Debug)]
pub enum QueryRejection {
    SignatureInvalid(SignatureError),
    StakingFailed(StakingError),
    OllamaError(String),
}

impl std::fmt::Display for QueryRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid(e) => write!(f, "Signature: {}", e),
            Self::StakingFailed(e) => write!(f, "Staking: {}", e),
            Self::OllamaError(e) => write!(f, "Ollama: {}", e),
        }
    }
}

impl OllamaInferenceTee {
    pub fn new(
        keypair: PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
        certificate: RootTrustCertificate,
        ollama_config: OllamaConfig,
        mining_threshold: MiningThreshold,
        operator: Address,
        max_reward: U256,
    ) -> Self {
        Self {
            keypair, tee_id, code_hash, certificate,
            sig_verifier: SignatureVerifier::new(),
            staking: StakingRegistry::new(),
            rate_limiter: RateLimiter::new(),
            ollama: OllamaClient::new(ollama_config),
            usage: UsageTracker::new(mining_threshold),
            round_id: 0, blocks_produced: 0, max_reward, operator,
            total_queries_all_time: 0, total_rejections: 0,
        }
    }

    /// Register a staker (in production: read from on-chain state).
    pub fn register_staker(&mut self, address: Address, amount: U256) {
        self.staking.set_stake(address, amount);
    }

    /// Process a signed query end-to-end.
    pub async fn process_query(&mut self, query: &SignedQuery) -> QueryResult {
        // Step 1: Verify EVM signature
        let verified = match self.sig_verifier.verify(query) {
            Ok(v) => v,
            Err(e) => {
                self.total_rejections += 1;
                return QueryResult::Rejected(QueryRejection::SignatureInvalid(e));
            }
        };

        // Step 2: Check staking
        let budget = match self.staking.check_stake(&verified.signer) {
            Ok(b) => b,
            Err(e) => {
                self.total_rejections += 1;
                return QueryResult::Rejected(QueryRejection::StakingFailed(e));
            }
        };

        // Step 3: Check rate limit
        if let Err(e) = self.rate_limiter.check_and_record(&verified.signer, &budget) {
            self.total_rejections += 1;
            return QueryResult::Rejected(QueryRejection::StakingFailed(e));
        }

        // Step 4: Forward to Ollama
        let start = std::time::Instant::now();
        let ollama_result = self
            .ollama
            .generate(&verified.model, &verified.query, verified.max_tokens)
            .await;

        let response = match ollama_result {
            Ok(r) => r,
            Err(e) => {
                self.total_rejections += 1;
                return QueryResult::Rejected(QueryRejection::OllamaError(e.to_string()));
            }
        };

        let latency_ms = start.elapsed().as_millis() as u64;

        // Step 5: Record usage
        let record = UsageRecord {
            user: verified.signer,
            model: verified.model.clone(),
            tokens_in: response.prompt_eval_count,
            tokens_out: response.eval_count,
            latency_ms,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.usage.record(record);
        self.total_queries_all_time += 1;

        QueryResult::Success {
            response: response.response,
            tokens_in: response.prompt_eval_count,
            tokens_out: response.eval_count,
            latency_ms,
            signer: verified.signer,
        }
    }

    /// Check if operator can mine a block.
    pub fn can_mine(&self) -> bool {
        self.usage.can_mine()
    }

    /// Mining progress (0.0 - 1.0+).
    pub fn mining_progress(&self) -> f64 {
        self.usage.mining_progress()
    }

    /// Produce a block with usage proof.
    pub fn produce_block(
        &mut self,
        parent_hash: B256,
    ) -> Result<SignedRoundComplete, Box<dyn std::error::Error>> {
        self.round_id += 1;
        let summary = self.usage.drain_for_block();

        // Reward goes to the operator
        let incentives = vec![PaymentInstruction {
            recipient: self.operator,
            amount: self.max_reward,
            is_reward: true,
        }];

        let tee_data = serde_json::to_vec(&serde_json::json!({
            "tee": "TEE-3 Ollama Inference",
            "model": self.ollama.model_name(),
            "queries_served": summary.total_queries,
            "tokens_processed": summary.total_tokens,
            "unique_users": summary.unique_users,
            "avg_latency_ms": summary.avg_latency_ms,
            "models_served": summary.models_served,
        }))?;

        let msg = RoundCompleteMessage {
            tee_id: self.tee_id,
            round_id: self.round_id,
            parent_block_hash: parent_hash,
            payments: vec![],
            incentives,
            timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: tee_data,
            transaction_hashes: vec![],
        };

        let sig = sign_message(&self.keypair, &msg.to_signing_bytes())?;

        let mut evidence = AttestationEvidence {
            tee_id: self.tee_id,
            enclave_measurement: self.code_hash,
            root_trust_cert: self.certificate.clone(),
            platform_data: PlatformData::Simulator {
                report: vec![0u8; 64],
                simulator_version: "3.0.0".to_string(),
            },
            nonce: B256::random(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            self_signature: vec![],
        };
        evidence.self_signature = sign_message(&self.keypair, &evidence.to_signing_bytes())?;

        self.blocks_produced += 1;

        Ok(SignedRoundComplete {
            message: msg,
            signature: sig,
            attestation_evidence: bincode::serialize(&evidence)?,
        })
    }

    /// Get current stats.
    pub fn stats(&self) -> TeeStats {
        TeeStats {
            model: self.ollama.model_name().to_string(),
            queries_pending: self.usage.query_count(),
            tokens_pending: self.usage.token_count(),
            unique_users_pending: self.usage.unique_users() as u32,
            mining_progress: self.mining_progress(),
            can_mine: self.can_mine(),
            total_queries_all_time: self.total_queries_all_time,
            total_rejections: self.total_rejections,
            blocks_produced: self.blocks_produced,
            stakers: self.staking.staker_count() as u32,
        }
    }
}

/// Runtime statistics.
#[derive(Debug, Clone)]
pub struct TeeStats {
    pub model: String,
    pub queries_pending: u64,
    pub tokens_pending: u64,
    pub unique_users_pending: u32,
    pub mining_progress: f64,
    pub can_mine: bool,
    pub total_queries_all_time: u64,
    pub total_rejections: u64,
    pub blocks_produced: u64,
    pub stakers: u32,
}

// ════════════════════════════════════════════════════════════════
// Simulator
// ════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  TEE-3: Ollama Inference Service                         ║");
    println!("║  EVM Wallet Auth · Staking Gated · Usage-Based Mining    ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // ── Phase 1: Initialize TEE ──
    println!("━━━ Phase 1: TEE Initialization ━━━\n");
    let keypair = PqcSigningKeypair::generate()?;
    let tee_id = TeeId::new({
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"tee3-ollama-inference");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hasher.finalize());
        arr
    });
    let code_hash = B256::from([0xDD; 32]);
    let cert = RootTrustCertificate {
        version: 1, subject_tee_id: tee_id, subject_code_hash: code_hash,
        subject_public_key: keypair.public_key_bytes().to_vec(),
        issued_at: chrono::Utc::now().timestamp() as u64, expires_at: 0,
        root_trust_signature: vec![0u8; 100],
    };

    let operator = Address::from([0xAA; 20]);
    let mut tee = OllamaInferenceTee::new(
        keypair, tee_id, code_hash, cert,
        OllamaConfig::simulated("llama3.2:1b"),
        MiningThreshold::test_mode(), // 5 queries or 100 tokens
        operator,
        U256::from(50_000_000_000_000_000_000u128), // 50 TEEC per block
    );
    println!("  Model:     {}", tee.ollama.model_name());
    println!("  Operator:  {}", operator);
    println!("  Mining:    5 queries or 100 tokens (test mode)");
    println!("  Prod mode: 1000 queries or 500K tokens\n");

    // ── Phase 2: Register Stakers ──
    println!("━━━ Phase 2: Register Stakers ━━━\n");
    // Create test wallets and register their stakes
    use signature::create_test_signed_query;

    // We'll create queries from different wallets
    let (sq1, addr1) = create_test_signed_query("What is Rust?", "llama3.2:1b", 1);
    let (sq2, addr2) = create_test_signed_query("Explain blockchains", "llama3.2:1b", 1);
    let (sq3, addr3) = create_test_signed_query("No stake user", "llama3.2:1b", 1);

    let teec = |n: u64| U256::from(n) * U256::from(1_000_000_000_000_000_000u128);

    tee.register_staker(addr1, teec(500));   // 500 TEEC → 500 queries/epoch
    tee.register_staker(addr2, teec(1000));  // 1000 TEEC → 1000 queries/epoch
    // addr3 has NO stake

    println!("  {} → 500 TEEC staked (500 queries/epoch)", addr1);
    println!("  {} → 1000 TEEC staked (1000 queries/epoch)", addr2);
    println!("  {} → NO STAKE (should be rejected)", addr3);
    println!("  Total stakers: {}\n", tee.staking.staker_count());

    // ── Phase 3: Process Signed Queries ──
    println!("━━━ Phase 3: Process Signed Queries ━━━\n");

    // Query from staked user 1 (should succeed)
    let result1 = tee.process_query(&sq1).await;
    match &result1 {
        QueryResult::Success { signer, tokens_in, tokens_out, latency_ms, response } => {
            println!("  ✓ Query from {} served", signer);
            println!("    Prompt: \"{}\"", sq1.query);
            println!("    Response: \"{}\"", &response[..response.len().min(80)]);
            println!("    Tokens: {} in, {} out, {}ms\n", tokens_in, tokens_out, latency_ms);
        }
        QueryResult::Rejected(e) => println!("  ✗ Unexpected rejection: {}\n", e),
    }

    // Query from staked user 2 (should succeed)
    let result2 = tee.process_query(&sq2).await;
    match &result2 {
        QueryResult::Success { signer, .. } => println!("  ✓ Query from {} served", signer),
        QueryResult::Rejected(e) => println!("  ✗ Unexpected rejection: {}", e),
    }

    // Query from unstaked user (should FAIL)
    let result3 = tee.process_query(&sq3).await;
    match &result3 {
        QueryResult::Success { .. } => println!("  ✗ Should have been rejected!"),
        QueryResult::Rejected(e) => println!("  ✓ Correctly rejected unstaked user: {}", e),
    }

    // Replay attack (should FAIL)
    let result_replay = tee.process_query(&sq1).await;
    match &result_replay {
        QueryResult::Success { .. } => println!("  ✗ Replay should have been rejected!"),
        QueryResult::Rejected(e) => println!("  ✓ Correctly rejected replay: {}", e),
    }

    println!("\n  Stats: {} served, {} rejected\n",
        tee.total_queries_all_time, tee.total_rejections);

    // ── Phase 4: Accumulate Enough Usage to Mine ──
    println!("━━━ Phase 4: Accumulate Usage → Mine Block ━━━\n");
    println!("  Mining progress: {:.0}%", tee.mining_progress() * 100.0);

    // Generate more queries to hit threshold
    for i in 2..=10 {
        let (sq, addr) = create_test_signed_query(
            &format!("Query number {}", i), "llama3.2:1b", i as u64,
        );
        tee.register_staker(addr, teec(100)); // Ensure they're staked
        let result = tee.process_query(&sq).await;
        let status = match &result {
            QueryResult::Success { .. } => "✓",
            QueryResult::Rejected(_) => "✗",
        };
        println!("  {} Query {} | progress: {:.0}% | can_mine: {}",
            status, i, tee.mining_progress() * 100.0, tee.can_mine());

        if tee.can_mine() {
            println!("\n  🎯 Mining threshold reached!");
            break;
        }
    }

    // ── Phase 5: Produce Block ──
    println!("\n━━━ Phase 5: Block Production ━━━\n");
    if tee.can_mine() {
        let block = tee.produce_block(B256::ZERO)?;
        println!("  Block produced:");
        println!("    Round:      {}", block.message.round_id);
        println!("    Reward:     {} wei → {}", block.message.incentives[0].amount, operator);

        // Parse tee_specific_data
        let data: serde_json::Value = serde_json::from_slice(&block.message.tee_specific_data)?;
        println!("    Queries:    {}", data["queries_served"]);
        println!("    Tokens:     {}", data["tokens_processed"]);
        println!("    Users:      {}", data["unique_users"]);
        println!("    Avg latency: {}ms", data["avg_latency_ms"]);
        println!("    Model:      {}", data["model"]);

        println!("\n  After mining: progress reset to {:.0}%", tee.mining_progress() * 100.0);
    } else {
        println!("  Not enough usage to mine yet ({:.0}%)", tee.mining_progress() * 100.0);
    }

    // ── Summary ──
    let stats = tee.stats();
    println!("\n━━━ Summary ━━━\n");
    println!("  Model:           {}", stats.model);
    println!("  Total served:    {} queries", stats.total_queries_all_time);
    println!("  Total rejected:  {}", stats.total_rejections);
    println!("  Blocks produced: {}", stats.blocks_produced);
    println!("  Stakers:         {}", stats.stakers);
    println!("  Unique signers:  {}", tee.sig_verifier.unique_signers());
    println!();

    Ok(())
}
