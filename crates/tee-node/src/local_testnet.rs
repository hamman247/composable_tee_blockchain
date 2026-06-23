//! Local Testnet — runs a live TEE-Chain network for a configurable duration.
//!
//! Usage: cargo run --release --bin local-testnet [-- --duration <seconds>]
//! Default: 180 seconds (3 minutes)
//!
//! This is NOT a programmatic test — it simulates a real running network with
//! all 4 TEEs producing blocks on realistic intervals, with minimal compute.

use tee_crypto::*;
use tee_types::*;
use tee_consensus::{TeeConsensusEngine, TeeRegistry};
use alloy_primitives::{Address, B256, U256};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

struct TestnetConfig {
    duration_secs: u64,
    tee1_interval: Duration,  // block coordinator interval
    tee2_interval: Duration,  // training step interval
    tee3_interval: Duration,  // inference batch interval
    tee4_interval: Duration,  // validator epoch interval
    tee3_mining_threshold: u64,
    tee4_uptime_threshold: Duration,
}

impl TestnetConfig {
    fn from_args() -> Self {
        let mut duration = 180u64;
        let args: Vec<String> = std::env::args().collect();
        for i in 0..args.len() {
            if args[i] == "--duration" || args[i] == "-d" {
                if let Some(v) = args.get(i + 1) {
                    duration = v.parse().unwrap_or(180);
                }
            }
        }
        Self {
            duration_secs: duration,
            tee1_interval: Duration::from_secs(3),
            tee2_interval: Duration::from_secs(5),
            tee3_interval: Duration::from_secs(4),
            tee4_interval: Duration::from_secs(6),
            tee3_mining_threshold: 10,
            tee4_uptime_threshold: Duration::from_secs(15),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// TEE state trackers
// ═══════════════════════════════════════════════════════════════

struct Tee3State {
    queries_served: u64,
    tokens_processed: u64,
    blocks_mined: u64,
}

struct Tee4State {
    validators: u32,
    attestations: u64,
    total_rewards_wei: U256,
    treasury_fees_wei: U256,
    pool_eth: U256,
    pool_shares: U256,
    blocks_mined: u64,
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn make_id(name: &[u8]) -> TeeId {
    let mut a = [0u8; 32];
    a.copy_from_slice(&Sha3_256::digest(name));
    TeeId::new(a)
}

fn make_hash(name: &[u8]) -> B256 {
    B256::from_slice(&Sha3_256::digest(name))
}

fn block_hash(num: u64, parent: B256) -> B256 {
    let mut h = Sha3_256::new();
    h.update(&num.to_le_bytes());
    h.update(parent.as_slice());
    B256::from_slice(&h.finalize())
}

fn certify(
    root: &PqcSigningKeypair, id: TeeId, code: B256, kp: &PqcSigningKeypair,
) -> Result<RootTrustCertificate, Box<dyn std::error::Error>> {
    let mut c = RootTrustCertificate {
        version: 1, subject_tee_id: id, subject_code_hash: code,
        subject_public_key: kp.public_key_bytes().to_vec(),
        issued_at: chrono::Utc::now().timestamp() as u64, expires_at: 0,
        root_trust_signature: vec![],
    };
    c.root_trust_signature = sign_message(root, &c.to_signing_bytes())?;
    Ok(c)
}

fn attest(
    kp: &PqcSigningKeypair, id: TeeId, code: B256, cert: &RootTrustCertificate,
) -> Result<AttestationEvidence, Box<dyn std::error::Error>> {
    let mut e = AttestationEvidence {
        tee_id: id, enclave_measurement: code, root_trust_cert: cert.clone(),
        platform_data: PlatformData::Simulator {
            report: vec![0u8; 64], simulator_version: "1.0.0".into(),
        },
        nonce: B256::random(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        self_signature: vec![],
    };
    e.self_signature = sign_message(kp, &e.to_signing_bytes())?;
    Ok(e)
}

fn produce_block(
    kp: &PqcSigningKeypair, root: &PqcSigningKeypair,
    id: TeeId, code: B256, cert: &RootTrustCertificate,
    round: u64, parent: B256,
    payments: Vec<PaymentInstruction>, incentives: Vec<PaymentInstruction>,
    data: Vec<u8>, txns: Vec<B256>,
    engine: &mut TeeConsensusEngine,
) -> Result<Option<SignedRoundComplete>, Box<dyn std::error::Error>> {
    let _ = root;
    let msg = RoundCompleteMessage {
        tee_id: id, round_id: round, parent_block_hash: parent,
        payments, incentives,
        timestamp: chrono::Utc::now().timestamp() as u64,
        tee_specific_data: data, transaction_hashes: txns,
    };
    let sig = sign_round_complete(kp, &msg)?;
    let ev = attest(kp, id, code, cert)?;
    let src = SignedRoundComplete {
        message: msg, signature: sig,
        attestation_evidence: bincode::serialize(&ev)?,
    };
    match engine.validate_block(&src.to_bytes(), parent) {
        Ok(_) => Ok(Some(src)),
        Err(e) => { eprintln!("    ✗ Block validation failed: {}", e); Ok(None) }
    }
}

fn elapsed_fmt(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}", s / 60, s % 60)
}

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = TestnetConfig::from_args();

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  TEE-Chain Local Testnet                                ║");
    println!("║  Running all 4 TEEs for {} seconds ({} min)             ║",
        cfg.duration_secs, cfg.duration_secs / 60);
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    // ── Setup Root Trust + keypairs ──
    let root_kp = PqcSigningKeypair::generate()?;
    let (kp1, id1, ch1) = (PqcSigningKeypair::generate()?, make_id(b"tee1-block-coordinator"), make_hash(b"tee1-v1"));
    let (kp2, id2, ch2) = (PqcSigningKeypair::generate()?, make_id(b"tee2-ai-training"), make_hash(b"tee2-v1"));
    let (kp3, id3, ch3) = (PqcSigningKeypair::generate()?, make_id(b"tee3-ollama-inference"), make_hash(b"tee3-v1"));
    let (kp4, id4, ch4) = (PqcSigningKeypair::generate()?, make_id(b"tee4-eth-validator"), make_hash(b"tee4-v1"));
    let c1 = certify(&root_kp, id1, ch1, &kp1)?;
    let c2 = certify(&root_kp, id2, ch2, &kp2)?;
    let c3 = certify(&root_kp, id3, ch3, &kp3)?;
    let c4 = certify(&root_kp, id4, ch4, &kp4)?;

    let ops = [Address::from([0x01;20]), Address::from([0x02;20]),
               Address::from([0x03;20]), Address::from([0x04;20])];

    // ── Registry ──
    let mut reg = TeeRegistry::new();
    reg.register(TeeRegistration {
        tee_id: TeeId::new([0xAA;32]), code_hash: B256::from([0xAA;32]),
        pqc_public_key: root_kp.public_key_bytes().to_vec(), root_trust_certificate: vec![],
        role: TeeRole::RootTrust, status: TeeStatus::Active, operator: ops[0],
        config: TeeConfig { name: "Root".into(), description: "".into(),
            api_endpoints: vec![], max_reward_per_block: U256::ZERO,
            mining_eligible: false, custom_params: vec![] },
        registered_at_block: 0,
    });
    for (i, (id, ch, kp, role)) in [
        (id1, ch1, &kp1, TeeRole::BlockCoordinator),
        (id2, ch2, &kp2, TeeRole::AiTraining),
        (id3, ch3, &kp3, TeeRole::OllamaInference),
        (id4, ch4, &kp4, TeeRole::EthValidator),
    ].iter().enumerate() {
        let cert_data = match i {
            0 => bincode::serialize(&c1)?,
            1 => bincode::serialize(&c2)?,
            2 => bincode::serialize(&c3)?,
            _ => bincode::serialize(&c4)?,
        };
        reg.register(TeeRegistration {
            tee_id: *id, code_hash: *ch,
            pqc_public_key: kp.public_key_bytes().to_vec(),
            root_trust_certificate: cert_data,
            role: *role, status: TeeStatus::Active, operator: ops[i],
            config: TeeConfig {
                name: format!("TEE-{}", i+1), description: "".into(),
                api_endpoints: vec![], max_reward_per_block: U256::from(50_000_000_000_000_000_000u128),
                mining_eligible: true, custom_params: vec![],
            },
            registered_at_block: 0,
        });
    }

    let mut engine = TeeConsensusEngine::with_config(
        root_kp.public_key_bytes().to_vec(), reg, TeeMode::Simulator,
        tee_consensus::RateLimitConfig::test(),
        tee_consensus::FairnessConfig::test(),
    );
    let mut balances: HashMap<Address, U256> = HashMap::new();
    for &op in &ops { balances.insert(op, U256::from(1000u64) * U256::from(1_000_000_000_000_000_000u128)); }

    let mut bn = 0u64;
    let mut bh = B256::ZERO;
    let mut round = [0u64; 4]; // per-TEE round counter

    // TEE-specific state
    let mut t3 = Tee3State { queries_served: 0, tokens_processed: 0, blocks_mined: 0 };
    let eth = |n: u64| U256::from(n) * U256::from(1_000_000_000_000_000_000u128);
    let mut t4 = Tee4State {
        validators: 3, attestations: 0,
        total_rewards_wei: U256::ZERO, treasury_fees_wei: U256::ZERO,
        pool_eth: eth(100), pool_shares: eth(100), blocks_mined: 0,
    };
    let mut tee2_step = 0u64;
    let mut tee2_loss = 10.0f64;

    println!("  Intervals: TEE-1={}s  TEE-2={}s  TEE-3={}s  TEE-4={}s",
        cfg.tee1_interval.as_secs(), cfg.tee2_interval.as_secs(),
        cfg.tee3_interval.as_secs(), cfg.tee4_interval.as_secs());
    println!("  TEE-3 mining: every {} queries", cfg.tee3_mining_threshold);
    println!("  TEE-4 mining: after {}s uptime\n", cfg.tee4_uptime_threshold.as_secs());

    let start = Instant::now();
    let deadline = Duration::from_secs(cfg.duration_secs);
    let mut last = [Instant::now(); 4];
    let mut tee4_can_mine = false;
    let mut total_valid = 0u64;
    let mut total_invalid = 0u64;

    println!("  [{} / {}] Network started — producing blocks...\n",
        elapsed_fmt(Duration::ZERO), elapsed_fmt(deadline));

    loop {
        let elapsed = start.elapsed();
        if elapsed >= deadline { break; }

        std::thread::sleep(Duration::from_millis(100)); // low CPU idle loop

        let now = Instant::now();

        // ── TEE-1: Block Coordinator ──
        if now.duration_since(last[0]) >= cfg.tee1_interval {
            last[0] = now;
            round[0] += 1;
            let result = produce_block(
                &kp1, &root_kp, id1, ch1, &c1, round[0], bh,
                vec![PaymentInstruction { recipient: ops[0], amount: U256::from(21000u64), is_reward: false }],
                vec![], vec![], vec![B256::random()], &mut engine,
            )?;
            if let Some(src) = result {
                bn += 1; bh = block_hash(bn, bh);
                for p in &src.message.payments { *balances.entry(p.recipient).or_insert(U256::ZERO) += p.amount; }
                total_valid += 1;
                println!("  [{}] TEE-1 Block #{:<4} round={}", elapsed_fmt(elapsed), bn, round[0]);
            } else { total_invalid += 1; }
        }

        // ── TEE-2: AI Training ──
        if now.duration_since(last[1]) >= cfg.tee2_interval {
            last[1] = now;
            round[1] += 1;
            tee2_step += 1;
            tee2_loss *= 0.98; // loss decreases
            let reward = U256::from(500_000_000_000_000_000u128); // 0.5 TEEC
            let result = produce_block(
                &kp2, &root_kp, id2, ch2, &c2, round[1], bh,
                vec![], vec![PaymentInstruction { recipient: ops[1], amount: reward, is_reward: true }],
                format!("{{\"step\":{},\"loss\":{:.4},\"checkpoint_hash\":\"{:016x}\"}}",
                    tee2_step, tee2_loss, tee2_step * 0xDEAD).into_bytes(),
                vec![], &mut engine,
            )?;
            if let Some(src) = result {
                bn += 1; bh = block_hash(bn, bh);
                for inc in &src.message.incentives { *balances.entry(inc.recipient).or_insert(U256::ZERO) += inc.amount; }
                total_valid += 1;
                println!("  [{}] TEE-2 Block #{:<4} step={} loss={:.4}", elapsed_fmt(elapsed), bn, tee2_step, tee2_loss);
            } else { total_invalid += 1; }
        }

        // ── TEE-3: Ollama Inference ──
        if now.duration_since(last[2]) >= cfg.tee3_interval {
            last[2] = now;
            // Simulate a batch of queries
            let batch = 3u64;
            t3.queries_served += batch;
            t3.tokens_processed += batch * 25;

            if t3.queries_served >= cfg.tee3_mining_threshold * (t3.blocks_mined + 1) {
                round[2] += 1;
                let reward = U256::from(50_000_000_000_000_000_000u128); // 50 TEEC
                let result = produce_block(
                    &kp3, &root_kp, id3, ch3, &c3, round[2], bh,
                    vec![], vec![PaymentInstruction { recipient: ops[2], amount: reward, is_reward: true }],
                    serde_json::to_vec(&serde_json::json!({
                        "queries": t3.queries_served, "tokens": t3.tokens_processed,
                    }))?,
                    vec![], &mut engine,
                )?;
                if let Some(src) = result {
                    bn += 1; bh = block_hash(bn, bh);
                    for inc in &src.message.incentives { *balances.entry(inc.recipient).or_insert(U256::ZERO) += inc.amount; }
                    t3.blocks_mined += 1;
                    total_valid += 1;
                    println!("  [{}] TEE-3 Block #{:<4} queries={} tokens={} ⛏",
                        elapsed_fmt(elapsed), bn, t3.queries_served, t3.tokens_processed);
                } else { total_invalid += 1; }
            } else {
                println!("  [{}] TEE-3 batch  +{} queries (total={}/{})",
                    elapsed_fmt(elapsed), batch, t3.queries_served,
                    cfg.tee3_mining_threshold * (t3.blocks_mined + 1));
            }
        }

        // ── TEE-4: ETH Validator ──
        if now.duration_since(last[3]) >= cfg.tee4_interval {
            last[3] = now;
            // Simulate epoch
            let epoch_reward = U256::from(2_500_000_000_000_000u128) * U256::from(t4.validators);
            let fee = (epoch_reward * U256::from(500u64)) / U256::from(10_000u64);
            t4.total_rewards_wei += epoch_reward;
            t4.treasury_fees_wei += fee;
            t4.pool_eth += epoch_reward - fee;
            t4.attestations += t4.validators as u64;

            if !tee4_can_mine && elapsed >= cfg.tee4_uptime_threshold {
                tee4_can_mine = true;
            }

            if tee4_can_mine {
                round[3] += 1;
                let reward = U256::from(25_000_000_000_000_000_000u128); // 25 TEEC
                let result = produce_block(
                    &kp4, &root_kp, id4, ch4, &c4, round[3], bh,
                    vec![], vec![PaymentInstruction { recipient: ops[3], amount: reward, is_reward: true }],
                    serde_json::to_vec(&serde_json::json!({
                        "validators": t4.validators, "attestations": t4.attestations,
                        "pool_eth": t4.pool_eth.to_string(),
                    }))?,
                    vec![], &mut engine,
                )?;
                if let Some(src) = result {
                    bn += 1; bh = block_hash(bn, bh);
                    for inc in &src.message.incentives { *balances.entry(inc.recipient).or_insert(U256::ZERO) += inc.amount; }
                    t4.blocks_mined += 1;
                    total_valid += 1;
                    println!("  [{}] TEE-4 Block #{:<4} vals={} atts={} ⛏",
                        elapsed_fmt(elapsed), bn, t4.validators, t4.attestations);
                } else { total_invalid += 1; }
                tee4_can_mine = false; // reset, must wait another uptime period
            } else {
                println!("  [{}] TEE-4 epoch  atts={} rewards={} (uptime: {}/{}s)",
                    elapsed_fmt(elapsed), t4.attestations, epoch_reward,
                    elapsed.as_secs(), cfg.tee4_uptime_threshold.as_secs());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Summary
    // ═══════════════════════════════════════════════════════════
    let runtime = start.elapsed();
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  Local Testnet Complete                                 ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");
    println!("  Runtime:          {}", elapsed_fmt(runtime));
    println!("  Total blocks:     {} ({} valid, {} invalid)", total_valid + total_invalid, total_valid, total_invalid);
    println!("  Block height:     {}", bn);
    println!("  Final hash:       {}", &hex::encode(bh.as_slice())[..16]);
    println!();
    println!("  TEE-1 blocks:     {} (coordinator)", round[0]);
    println!("  TEE-2 blocks:     {} (training, loss={:.4})", round[1], tee2_loss);
    println!("  TEE-3 blocks:     {} (inference, {} queries, {} tokens)", t3.blocks_mined, t3.queries_served, t3.tokens_processed);
    println!("  TEE-4 blocks:     {} (validator, {} atts, {} validators)", t4.blocks_mined, t4.attestations, t4.validators);
    println!();
    println!("  Balances:");
    let mut sorted: Vec<_> = balances.iter().collect();
    sorted.sort_by_key(|(a,_)| **a);
    for (addr, bal) in &sorted {
        let teec = *bal / U256::from(1_000_000_000_000_000_000u128);
        println!("    {} → {} TEEC", addr, teec);
    }

    let bps = if runtime.as_secs() > 0 { bn as f64 / runtime.as_secs_f64() } else { 0.0 };
    println!("\n  Throughput:       {:.2} blocks/sec", bps);
    println!("  Avg interval:     {:.1}s", if bn > 0 { runtime.as_secs_f64() / bn as f64 } else { 0.0 });

    if total_invalid == 0 && bn > 0 {
        println!("\n  ✅ TESTNET RAN SUCCESSFULLY — {} blocks over {}", bn, elapsed_fmt(runtime));
    } else if total_invalid > 0 {
        println!("\n  ⚠️  TESTNET COMPLETED WITH {} INVALID BLOCKS", total_invalid);
    } else {
        println!("\n  ❌ TESTNET PRODUCED NO BLOCKS");
    }
    println!();

    Ok(())
}
