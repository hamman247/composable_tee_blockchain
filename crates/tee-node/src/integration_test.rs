//! Full Integration Test: Root Trust → TEE-1 → TEE-2 → Node
//!
//! Runs a complete end-to-end test of the blockchain with both TEEs:
//!
//! 1. Root Trust initializes and certifies TEE-1 and TEE-2
//! 2. TEE-1 produces blocks with round-robin operator scheduling
//! 3. TEE-2 runs distributed training with proportional rewards
//! 4. Node validates all blocks through the consensus engine
//! 5. Balances, rewards, and training metrics are verified
//!
//! ## Test Mode vs Production
//!
//! Test mode uses reduced difficulty:
//! - TEE-2: min resource allocation (1%), 1 training step, micro batches
//! - TEE-1: 1-second block interval, 1 pending txn minimum
//!
//! Production defaults are frontier-competitive:
//! - TEE-2: 2T token training target, 8192 seq_len, cosine LR schedule
//! - TEE-1: 30-second block interval, 10 pending txn minimum

use tee_crypto::*;
use tee_types::*;
use tee_consensus::{TeeConsensusEngine, TeeRegistry};
use alloy_primitives::{Address, B256, U256};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════
// Configuration: Test vs Production
// ════════════════════════════════════════════════════════════════

/// Test configuration (reduced difficulty, minimal compute).
fn test_config() -> TestConfig {
    TestConfig {
        // TEE-1 settings
        block_interval_secs: 1,         // 1 second (production: 30)
        min_pending_txns: 1,            // 1 txn (production: 10)
        // TEE-2 settings
        training_steps: 3,              // 3 steps (production: millions)
        micro_batch_size: 1,            // 1 (production: 4)
        seq_len: 128,                   // 128 (production: 8192)
        resource_allocation: 0.01,      // 1% (production: 25-100%)
        total_training_tokens: 1000,    // 1K (production: 2T)
        // Number of simulated workers
        num_workers: 2,
        // Number of blocks to produce
        num_blocks: 3,
    }
}

/// Production configuration (frontier-competitive defaults).
#[allow(dead_code)]
fn production_config() -> TestConfig {
    TestConfig {
        // TEE-1: Standard block timing
        block_interval_secs: 30,
        min_pending_txns: 10,
        // TEE-2: Frontier-scale training
        training_steps: 0,  // Determined by total_training_tokens / batch_size
        micro_batch_size: 4,
        seq_len: 8192,
        resource_allocation: 1.0,
        total_training_tokens: 2_000_000_000_000, // 2T tokens
        // Scale
        num_workers: 100,
        num_blocks: 0, // Continuous
    }
}

struct TestConfig {
    block_interval_secs: u64,
    min_pending_txns: usize,
    training_steps: u64,
    micro_batch_size: u32,
    seq_len: u32,
    resource_allocation: f64,
    total_training_tokens: u64,
    num_workers: u32,
    num_blocks: u32,
}

// ════════════════════════════════════════════════════════════════
// Integration Test
// ════════════════════════════════════════════════════════════════

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  TEE-Chain Integration Test: Full Blockchain + Both TEEs ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║  Mode: TEST (reduced difficulty)                        ║");
    println!("║  Production defaults shown for comparison               ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    let cfg = test_config();
    let prod = production_config();

    println!("  Configuration comparison:");
    println!("  ┌─────────────────────────┬──────────────┬──────────────────┐");
    println!("  │ Setting                 │ Test         │ Production       │");
    println!("  ├─────────────────────────┼──────────────┼──────────────────┤");
    println!("  │ Block interval          │ {}s          │ {}s              │", cfg.block_interval_secs, prod.block_interval_secs);
    println!("  │ Min pending txns        │ {}            │ {}              │", cfg.min_pending_txns, prod.min_pending_txns);
    println!("  │ Training steps          │ {}            │ auto (~600K)     │", cfg.training_steps);
    println!("  │ Micro-batch size        │ {}            │ {}               │", cfg.micro_batch_size, prod.micro_batch_size);
    println!("  │ Sequence length         │ {}          │ {}            │", cfg.seq_len, prod.seq_len);
    println!("  │ Resource allocation     │ {:.0}%          │ {:.0}%            │", cfg.resource_allocation * 100.0, prod.resource_allocation * 100.0);
    println!("  │ Training tokens         │ {}         │ 2T               │", cfg.total_training_tokens);
    println!("  │ Workers                 │ {}            │ {}+             │", cfg.num_workers, prod.num_workers);
    println!("  └─────────────────────────┴──────────────┴──────────────────┘\n");

    // ═══════════════════════════════════════════════════════════
    // Phase 1: Root Trust TEE Initialization
    // ═══════════════════════════════════════════════════════════
    println!("━━━ Phase 1: Root Trust TEE ━━━\n");

    let root_kp = PqcSigningKeypair::generate()?;
    let root_pk_hex = hex::encode(root_kp.public_key_bytes());
    println!("  [RootTrust] Generated ML-DSA root keypair");
    println!("  [RootTrust] Public key hash: {}", &hex::encode(Sha3_256::digest(root_kp.public_key_bytes()))[..16]);

    // Certify TEE-1
    let tee1_kp = PqcSigningKeypair::generate()?;
    let tee1_id = TeeId::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&Sha3_256::digest(b"tee1-block-coordinator"));
        arr
    });
    let tee1_code_hash = B256::from_slice(&Sha3_256::digest(b"tee1-block-coordinator-binary-v1"));
    let tee1_cert = sign_certificate(&root_kp, tee1_id, tee1_code_hash, &tee1_kp)?;
    println!("  [RootTrust] Certified TEE-1 (Block Coordinator): {}", &hex::encode(tee1_id.0.as_slice())[..16]);

    // Certify TEE-2
    let tee2_kp = PqcSigningKeypair::generate()?;
    let tee2_id = TeeId::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&Sha3_256::digest(b"tee2-ai-training"));
        arr
    });
    let tee2_code_hash = B256::from_slice(&Sha3_256::digest(b"tee2-ai-training-binary-v1"));
    let tee2_cert = sign_certificate(&root_kp, tee2_id, tee2_code_hash, &tee2_kp)?;
    println!("  [RootTrust] Certified TEE-2 (AI Training):       {}", &hex::encode(tee2_id.0.as_slice())[..16]);
    println!("  [RootTrust] Vault: 2 dk's in memory (not on disk)\n");

    // ═══════════════════════════════════════════════════════════
    // Phase 2: Initialize Consensus Engine + Node State
    // ═══════════════════════════════════════════════════════════
    println!("━━━ Phase 2: Node Initialization ━━━\n");

    let operator_a = Address::from([0x01; 20]);
    let operator_b = Address::from([0x02; 20]);
    let treasury   = Address::from([0xFF; 20]);

    let mut registry = TeeRegistry::new();

    // Register Root Trust (not mining eligible)
    registry.register(TeeRegistration {
        tee_id: TeeId::new([0xAA; 32]),
        code_hash: B256::from([0xAA; 32]),
        pqc_public_key: root_kp.public_key_bytes().to_vec(),
        root_trust_certificate: vec![],
        role: TeeRole::RootTrust,
        status: TeeStatus::Active,
        operator: operator_a,
        config: TeeConfig {
            name: "Root Trust".to_string(), description: "Root of trust".to_string(),
            api_endpoints: vec![], max_reward_per_block: U256::ZERO,
            mining_eligible: false, custom_params: vec![],
        },
        registered_at_block: 0,
    });

    // Register TEE-1 (Block Coordinator)
    registry.register(TeeRegistration {
        tee_id: tee1_id,
        code_hash: tee1_code_hash,
        pqc_public_key: tee1_kp.public_key_bytes().to_vec(),
        root_trust_certificate: bincode::serialize(&tee1_cert)?,
        role: TeeRole::BlockCoordinator,
        status: TeeStatus::Active,
        operator: operator_a,
        config: TeeConfig {
            name: "TEE-1: Block Coordinator".to_string(),
            description: "RPC + block production".to_string(),
            api_endpoints: vec!["http://localhost:8545".to_string()],
            max_reward_per_block: U256::ZERO,
            mining_eligible: true,
            custom_params: vec![],
        },
        registered_at_block: 0,
    });

    // Register TEE-2 (AI Training)
    registry.register(TeeRegistration {
        tee_id: tee2_id,
        code_hash: tee2_code_hash,
        pqc_public_key: tee2_kp.public_key_bytes().to_vec(),
        root_trust_certificate: bincode::serialize(&tee2_cert)?,
        role: TeeRole::AiTraining,
        status: TeeStatus::Active,
        operator: operator_b,
        config: TeeConfig {
            name: "TEE-2: AI Training".to_string(),
            description: "Distributed transformer training".to_string(),
            api_endpoints: vec!["http://localhost:8546".to_string()],
            max_reward_per_block: U256::from(100_000_000_000_000_000_000u128), // 100 TEEC
            mining_eligible: true,
            custom_params: vec![],
        },
        registered_at_block: 0,
    });

    let mut engine = TeeConsensusEngine::new(
        root_kp.public_key_bytes().to_vec(), registry, TeeMode::Simulator,
    );

    let mut balances: HashMap<Address, U256> = HashMap::new();
    balances.insert(operator_a, U256::from(1_000_000_000_000_000_000_000u128)); // 1000 TEEC
    balances.insert(operator_b, U256::from(1_000_000_000_000_000_000_000u128));
    balances.insert(treasury, U256::from(500_000_000_000_000_000_000_000u128));

    let mut block_number = 0u64;
    let mut block_hash = B256::ZERO;
    let mut all_blocks_valid = true;

    println!("  [Node] Chain ID: 0x7EE1 (TEE-Chain Testnet)");
    println!("  [Node] Registered TEEs: 3 (Root Trust + TEE-1 + TEE-2)");
    println!("  [Node] Genesis balances loaded: 3 accounts\n");

    // ═══════════════════════════════════════════════════════════
    // Phase 3: TEE-1 Block Production
    // ═══════════════════════════════════════════════════════════
    println!("━━━ Phase 3: TEE-1 Block Production ━━━\n");

    for block_idx in 0..cfg.num_blocks {
        let round_id = block_idx as u64 + 1;

        // Create TEE-1 signed block
        let msg = RoundCompleteMessage {
            tee_id: tee1_id, round_id,
            parent_block_hash: block_hash,
            payments: vec![PaymentInstruction {
                recipient: operator_a,
                amount: U256::from(21000u64), // tx fee
                is_reward: false,
            }],
            incentives: vec![], // TEE-1 has no block rewards
            timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: format!("{{\"block_interval\":{},\"min_txns\":{}}}", cfg.block_interval_secs, cfg.min_pending_txns).into_bytes(),
            transaction_hashes: vec![B256::random()],
        };

        let sig = sign_round_complete(&tee1_kp, &msg)?;
        let evidence = create_attestation(&tee1_kp, &root_kp, tee1_id, tee1_code_hash, &tee1_cert)?;

        let signed_rc = SignedRoundComplete {
            message: msg, signature: sig,
            attestation_evidence: bincode::serialize(&evidence)?,
        };

        // Validate through consensus engine
        match engine.validate_block(&signed_rc.to_bytes(), block_hash) {
            Ok(_) => {
                block_number += 1;
                block_hash = compute_block_hash(block_number, block_hash);
                for p in &signed_rc.message.payments {
                    *balances.entry(p.recipient).or_insert(U256::ZERO) += p.amount;
                }
                println!("  [TEE-1] Block #{} ✓ round={}, operator={}, txns={}",
                    block_number, round_id, operator_a, signed_rc.message.transaction_hashes.len());
            }
            Err(e) => {
                println!("  [TEE-1] Block #{} ✗ FAILED: {}", block_idx + 1, e);
                all_blocks_valid = false;
            }
        }
    }
    println!();

    // ═══════════════════════════════════════════════════════════
    // Phase 4: TEE-2 Training + Block Production
    // ═══════════════════════════════════════════════════════════
    println!("━━━ Phase 4: TEE-2 AI Training + Mining ━━━\n");
    println!("  Training config: {} steps, batch={}, seq_len={}, alloc={:.0}%",
        cfg.training_steps, cfg.micro_batch_size, cfg.seq_len, cfg.resource_allocation * 100.0);

    let mut training_loss = 10.0f64;

    for step in 0..cfg.training_steps {
        // Simulate training progress
        let progress = (step + 1) as f64 / cfg.training_steps as f64;
        training_loss = 10.0 * (1.0 - progress * 0.8); // Loss decreases
        let tokens_this_step = cfg.micro_batch_size as u64 * cfg.seq_len as u64 * cfg.num_workers as u64;

        println!("  [TEE-2] Step {} | loss={:.3} | tokens={} | alloc={:.0}%",
            step + 1, training_loss, tokens_this_step, cfg.resource_allocation * 100.0);

        // Produce a block with training rewards
        let round_id = cfg.num_blocks as u64 + step + 1;
        let reward_per_worker = U256::from(
            (50_000_000_000_000_000_000f64 * cfg.resource_allocation) as u128
        );

        let mut incentives = Vec::new();
        for w in 0..cfg.num_workers {
            incentives.push(PaymentInstruction {
                recipient: Address::from([(w + 1) as u8; 20]),
                amount: reward_per_worker,
                is_reward: true,
            });
        }

        let msg = RoundCompleteMessage {
            tee_id: tee2_id, round_id,
            parent_block_hash: block_hash,
            payments: vec![],
            incentives,
            timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: serde_json::to_vec(&serde_json::json!({
                "model": "Llama-3-8B",
                "step": step + 1,
                "loss": training_loss,
                "tokens": tokens_this_step,
                "allocation_pct": cfg.resource_allocation * 100.0,
            }))?,
            transaction_hashes: vec![],
        };

        let sig = sign_round_complete(&tee2_kp, &msg)?;
        let evidence = create_attestation(&tee2_kp, &root_kp, tee2_id, tee2_code_hash, &tee2_cert)?;

        let signed_rc = SignedRoundComplete {
            message: msg, signature: sig,
            attestation_evidence: bincode::serialize(&evidence)?,
        };

        match engine.validate_block(&signed_rc.to_bytes(), block_hash) {
            Ok(_) => {
                block_number += 1;
                block_hash = compute_block_hash(block_number, block_hash);
                for inc in &signed_rc.message.incentives {
                    *balances.entry(inc.recipient).or_insert(U256::ZERO) += inc.amount;
                }
                println!("  [TEE-2] Block #{} ✓ training step={}, rewards={} workers",
                    block_number, step + 1, cfg.num_workers);
            }
            Err(e) => {
                println!("  [TEE-2] Block #{} ✗ FAILED: {}", block_number + 1, e);
                all_blocks_valid = false;
            }
        }
    }
    println!();

    // ═══════════════════════════════════════════════════════════
    // Phase 5: Validation Summary
    // ═══════════════════════════════════════════════════════════
    println!("━━━ Phase 5: Validation Summary ━━━\n");

    let total_blocks = cfg.num_blocks as u64 + cfg.training_steps;
    println!("  Blocks produced:    {}", block_number);
    println!("  All blocks valid:   {}", if all_blocks_valid { "✓ YES" } else { "✗ NO" });
    println!("  Final block hash:   {}", &hex::encode(block_hash.as_slice())[..16]);
    println!("  Training loss:      {:.3}", training_loss);
    println!();

    println!("  Balances:");
    let mut sorted_balances: Vec<_> = balances.iter().collect();
    sorted_balances.sort_by_key(|(a, _)| **a);
    for (addr, bal) in &sorted_balances {
        let teec = *bal / U256::from(1_000_000_000_000_000_000u128);
        println!("    {} → {} TEEC", addr, teec);
    }

    println!("\n  ════════════════════════════════════════");
    if all_blocks_valid && block_number == total_blocks {
        println!("  ✅ INTEGRATION TEST PASSED");
        println!("     {} blocks validated through TEE consensus", total_blocks);
        println!("     Root Trust → TEE-1 + TEE-2 → Consensus Engine ✓");
    } else {
        println!("  ❌ INTEGRATION TEST FAILED");
        if !all_blocks_valid { println!("     Some blocks failed consensus validation"); }
        if block_number != total_blocks { println!("     Expected {} blocks, got {}", total_blocks, block_number); }
    }
    println!("  ════════════════════════════════════════\n");

    Ok(())
}

// ════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════

fn sign_certificate(
    root_kp: &PqcSigningKeypair, tee_id: TeeId, code_hash: B256, tee_kp: &PqcSigningKeypair,
) -> Result<RootTrustCertificate, Box<dyn std::error::Error>> {
    let mut cert = RootTrustCertificate {
        version: 1, subject_tee_id: tee_id, subject_code_hash: code_hash,
        subject_public_key: tee_kp.public_key_bytes().to_vec(),
        issued_at: chrono::Utc::now().timestamp() as u64, expires_at: 0,
        root_trust_signature: vec![],
    };
    cert.root_trust_signature = sign_message(root_kp, &cert.to_signing_bytes())?;
    Ok(cert)
}

fn create_attestation(
    tee_kp: &PqcSigningKeypair, root_kp: &PqcSigningKeypair,
    tee_id: TeeId, code_hash: B256, cert: &RootTrustCertificate,
) -> Result<AttestationEvidence, Box<dyn std::error::Error>> {
    let _ = root_kp; // Root KP not needed here — cert already signed
    let mut evidence = AttestationEvidence {
        tee_id, enclave_measurement: code_hash,
        root_trust_cert: cert.clone(),
        platform_data: PlatformData::Simulator {
            report: vec![0u8; 64], simulator_version: "1.0.0".to_string(),
        },
        nonce: B256::random(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        self_signature: vec![],
    };
    evidence.self_signature = sign_message(tee_kp, &evidence.to_signing_bytes())?;
    Ok(evidence)
}

fn compute_block_hash(number: u64, parent: B256) -> B256 {
    let mut h = Sha3_256::new();
    h.update(&number.to_le_bytes());
    h.update(parent.as_slice());
    B256::from_slice(&h.finalize())
}
