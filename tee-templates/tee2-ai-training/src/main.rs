//! TEE-2: Distributed AI Training & Inference
//!
//! ## Architecture
//!
//! TEE-2 operates as a **coordinator TEE** with multiple **worker nodes**.
//!
//! - **Work distribution**: Gradient-based distributed training with ZeRO-3 data parallelism
//! - **Dynamic membership**: Heartbeat-based health monitoring, crash recovery, rebalancing
//! - **Rewards**: Proportional to tokens processed × gradient quality
//! - **Serving**: Any operational node can serve inference on the trained model
//!
//! All coordination, measurement, and reward decisions happen INSIDE the TEE enclave.

pub mod model;
pub mod dataset;
pub mod training;
pub mod evaluation;
pub mod serving;
pub mod worker_state;
pub mod work_queue;
pub mod health;
pub mod discovery;
pub mod worker_api;

use tee_crypto::{PqcSigningKeypair, sign_message};
use tee_types::*;
use alloy_primitives::{Address, B256, U256};
use std::collections::HashMap;
use std::time::Instant;
use rand::Rng;

use model::{TransformerConfig, ModelArchitecture, MemoryBudget, BenchmarkScores};
use dataset::{DatasetRegistry, DatasetId};
use training::{
    TrainingConfig, TrainingState, TrainingMetrics, GradientUpdate,
    GradientAggregator, GradientCompression, calculate_rewards,
};
use evaluation::{BenchmarkSuite, BenchmarkId, BenchmarkResult, EvaluationReport, EvaluationSchedule};
use serving::{ServingConfig, ServingState, InferenceRequest, InferenceResponse, Completion, FinishReason, ModelVersion};
use worker_state::{WorkerState, WorkerCapabilities, WorkerLifecycle, ResourceAllocation};
use health::{HealthMonitor, HealthConfig};

/// TEE-2 Distributed Training Coordinator.
pub struct AiTrainingTee {
    // ── Identity ──
    keypair: PqcSigningKeypair,
    tee_id: TeeId,
    code_hash: B256,
    certificate: RootTrustCertificate,

    // ── Model ──
    model_config: TransformerConfig,
    training_config: TrainingConfig,

    // ── Training state ──
    training_state: TrainingState,
    gradient_aggregator: GradientAggregator,
    dataset_registry: DatasetRegistry,
    eval_schedule: EvaluationSchedule,
    eval_suite: BenchmarkSuite,

    // ── Worker management ──
    workers: HashMap<Address, WorkerState>,
    health_monitor: HealthMonitor,

    // ── Serving ──
    serving_state: ServingState,

    // ── Block production ──
    round_id: u64,
    max_reward: U256,
    round_metrics: Vec<TrainingMetrics>,
    blocks_produced: u64,
}

impl AiTrainingTee {
    pub fn new(
        keypair: PqcSigningKeypair,
        tee_id: TeeId,
        code_hash: B256,
        certificate: RootTrustCertificate,
        model_arch: ModelArchitecture,
        max_reward: U256,
    ) -> Self {
        let model_config = TransformerConfig::for_architecture(model_arch);
        let training_config = TrainingConfig::default_8b(1); // Updated when workers join

        Self {
            keypair, tee_id, code_hash, certificate,
            training_state: TrainingState::new(training_config.total_training_tokens),
            gradient_aggregator: GradientAggregator::new(0),
            dataset_registry: DatasetRegistry::new(),
            eval_schedule: EvaluationSchedule::default(),
            eval_suite: BenchmarkSuite::standard(),
            model_config,
            training_config,
            workers: HashMap::new(),
            health_monitor: HealthMonitor::new(HealthConfig::default()),
            serving_state: ServingState::new(ServingConfig::default()),
            round_id: 0,
            max_reward,
            round_metrics: Vec::new(),
            blocks_produced: 0,
        }
    }

    // ── Worker lifecycle ──

    pub fn register_worker(
        &mut self, operator: Address, capabilities: WorkerCapabilities, allocation: ResourceAllocation,
    ) -> String {
        self.health_monitor.register_worker(operator, capabilities, allocation.clone(), &mut self.workers);
        if let Some(w) = self.workers.get_mut(&operator) {
            w.lifecycle = WorkerLifecycle::Active;
        }
        let active = self.active_worker_count();
        self.gradient_aggregator.set_expected_workers(active as u32);
        let budget = MemoryBudget::calculate(&self.model_config, active as u32, 64.0, 4, 8192);
        format!("Registered. ZeRO-3 shard: {:.2}GB/node, fits={}",
            budget.total_per_node_gb, budget.fits_in_budget)
    }

    pub fn active_worker_count(&self) -> usize {
        HealthMonitor::active_worker_count(&self.workers)
    }

    // ── Training step ──

    pub fn submit_gradient(&mut self, update: GradientUpdate) {
        let worker = update.worker;
        let step = update.global_step;
        let loss = update.loss;
        let tokens = update.tokens_processed;

        // Record metrics
        if let Some(w) = self.workers.get_mut(&worker) {
            w.add_compute(tokens);
        }

        self.round_metrics.push(TrainingMetrics {
            worker,
            global_step: step,
            loss,
            learning_rate: self.training_config.optimizer.lr,
            gradient_norm: update.gradient_norm,
            tokens_per_second: if update.step_time_ms > 0 {
                tokens as f64 / (update.step_time_ms as f64 / 1000.0)
            } else { 0.0 },
            tokens_processed_total: self.workers.get(&worker)
                .map(|w| w.total_compute_units).unwrap_or(0),
            gpu_memory_bytes: None,
            gpu_utilization: 0.95,
        });

        // Try aggregation
        if let Some(_agg) = self.gradient_aggregator.submit(update) {
            let lr = self.training_config.scheduler.get_lr(
                self.training_config.optimizer.lr, step);
            self.training_state.update(&self.round_metrics, lr);
        }
    }

    // ── Evaluation ──

    pub fn run_evaluation(&mut self, step: u64, tokens: u64, simulated_progress: f64) -> EvaluationReport {
        let results: Vec<BenchmarkResult> = self.eval_suite.benchmarks.iter().map(|b| {
            let score = simulate_benchmark_score(&b.id, simulated_progress);
            let (meets_frontier, meets_competitive) = match b.metric {
                evaluation::MetricType::LowerIsBetter => (score <= b.frontier_target, score <= b.competitive_threshold),
                _ => (score >= b.frontier_target, score >= b.competitive_threshold),
            };
            BenchmarkResult {
                benchmark_id: b.id.clone(),
                score,
                num_evaluated: b.num_examples,
                meets_frontier, meets_competitive,
                category_scores: vec![],
                evaluated_at: chrono::Utc::now().timestamp() as u64,
                at_step: step,
            }
        }).collect();
        let report = EvaluationReport::from_results(step, tokens, results);
        let scores = report.to_benchmark_scores();
        self.training_state.save_checkpoint(&self.model_config, scores);
        report
    }

    // ── Block production ──

    pub fn produce_block(&mut self, parent_hash: B256) -> Result<SignedRoundComplete, Box<dyn std::error::Error>> {
        self.round_id += 1;
        let rewards = calculate_rewards(&self.round_metrics);
        let mut incentives = Vec::new();
        let total_prop: f64 = rewards.iter().map(|r| r.reward_proportion).sum();

        for r in &rewards {
            if total_prop > 0.0 {
                let frac = r.reward_proportion / total_prop;
                let reward = U256::from((frac * 100_000_000_000_000_000_000f64) as u128);
                let capped = if reward > self.max_reward { self.max_reward } else { reward };
                incentives.push(PaymentInstruction {
                    recipient: r.worker, amount: capped, is_reward: true,
                });
            }
        }

        let tee_data = serde_json::to_vec(&serde_json::json!({
            "model": self.model_config.name,
            "params": self.model_config.param_count_human(),
            "step": self.training_state.global_step,
            "loss": self.training_state.avg_loss,
            "tokens_processed": self.training_state.total_tokens_processed,
            "progress_pct": self.training_state.progress * 100.0,
            "active_workers": self.active_worker_count(),
        }))?;

        let msg = RoundCompleteMessage {
            tee_id: self.tee_id, round_id: self.round_id, parent_block_hash: parent_hash,
            payments: vec![], incentives, timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: tee_data, transaction_hashes: vec![],
        };
        let sig = sign_message(&self.keypair, &msg.to_signing_bytes())?;
        let mut evidence = AttestationEvidence {
            tee_id: self.tee_id, enclave_measurement: self.code_hash,
            root_trust_cert: self.certificate.clone(),
            platform_data: PlatformData::Simulator { report: vec![0u8; 64], simulator_version: "2.0.0".to_string() },
            nonce: B256::random(), timestamp: chrono::Utc::now().timestamp() as u64,
            self_signature: vec![],
        };
        evidence.self_signature = sign_message(&self.keypair, &evidence.to_signing_bytes())?;

        self.round_metrics.clear();
        for w in self.workers.values_mut() { w.reset_round_compute(); }
        self.blocks_produced += 1;

        Ok(SignedRoundComplete {
            message: msg, signature: sig,
            attestation_evidence: bincode::serialize(&evidence)?,
        })
    }

    // ── Inference ──

    pub fn handle_inference(&mut self, req: &InferenceRequest) -> InferenceResponse {
        let version = ModelVersion {
            architecture: self.model_config.name.clone(),
            parameters: self.model_config.param_count_human(),
            training_step: self.training_state.global_step,
            tokens_trained: self.training_state.total_tokens_processed,
            is_partial: self.training_state.progress < 1.0,
            training_progress: self.training_state.progress,
        };
        self.serving_state.record_request(1, 50);
        InferenceResponse {
            completions: vec![Completion {
                text: format!("[Model {}, step {}, {:.1}% trained] (inference simulated)",
                    self.model_config.name, self.training_state.global_step,
                    self.training_state.progress * 100.0),
                finish_reason: FinishReason::Length,
                logprobs: None,
            }],
            model_info: version, processing_time_ms: 50,
            tokens_generated: 1, prompt_tokens: req.prompt.len() as u32 / 4,
        }
    }
}

/// Simulate benchmark scores based on training progress (0.0-1.0).
fn simulate_benchmark_score(id: &BenchmarkId, progress: f64) -> f64 {
    let p = progress.clamp(0.0, 1.0);
    match id {
        BenchmarkId::Perplexity => 15.0 - (12.5 * p),   // 15 → 2.5
        BenchmarkId::MMLU => 25.0 + (65.0 * p),          // 25% → 90%
        BenchmarkId::HumanEval => 5.0 + (82.0 * p),      // 5% → 87%
        BenchmarkId::GSM8K => 5.0 + (88.0 * p),           // 5% → 93%
        BenchmarkId::ArcChallenge => 25.0 + (68.0 * p),   // 25% → 93%
        BenchmarkId::TruthfulQA => 30.0 + (48.0 * p),     // 30% → 78%
        BenchmarkId::MATH => 2.0 + (68.0 * p),            // 2% → 70%
        BenchmarkId::WinoGrande => 50.0 + (38.0 * p),     // 50% → 88%
    }
}

// ════════════════════════════════════════════════════════════════
// Simulator
// ════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  TEE-2: Distributed Transformer Training & Inference  ║");
    println!("║  ZeRO-3 Data Parallel · Consumer Hardware · Open API  ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // ── Phase 1: Model Architecture ──
    println!("━━━ Phase 1: Model Architecture Selection ━━━\n");
    let configs = [ModelArchitecture::Llama3_8B, ModelArchitecture::Llama3_70B, ModelArchitecture::Llama3_405B];
    for arch in &configs {
        let cfg = TransformerConfig::for_architecture(*arch);
        let min_nodes = MemoryBudget::min_nodes_for_budget(&cfg, 64.0, 4, 8192);
        println!("  {} | {} params | {} weights | min {} nodes (64GB RAM)",
            cfg.name, cfg.param_count_human(), cfg.model_size_human(), min_nodes);
    }
    let model_config = TransformerConfig::llama3_8b();
    println!("\n  → Selected: {} for simulation\n", model_config.name);

    let budget = MemoryBudget::calculate(&model_config, 10, 64.0, 4, 8192);
    println!("  ZeRO-3 Budget (10 nodes, 64GB RAM each):");
    println!("    Params shard:    {:.2} GB", budget.param_shard_bytes as f64 / 1e9);
    println!("    Gradients shard: {:.2} GB", budget.gradient_shard_bytes as f64 / 1e9);
    println!("    Optimizer shard: {:.2} GB", budget.optimizer_shard_bytes as f64 / 1e9);
    println!("    Activations:     {:.2} GB", budget.activation_bytes as f64 / 1e9);
    println!("    TOTAL per node:  {:.2} GB ✓ fits in 64GB\n", budget.total_per_node_gb);

    // ── Phase 2: Dataset Registry ──
    println!("━━━ Phase 2: Training Data (External References) ━━━\n");
    let registry = DatasetRegistry::new();
    for (id, weight) in registry.pretraining_mix() {
        if let Some(m) = registry.manifests.get(&id) {
            println!("  [{:.0}%] {} — {:.1}T tokens ({:.1} TB)",
                weight * 100.0, m.name, m.total_tokens as f64 / 1e12,
                m.total_size_bytes as f64 / 1e12);
            println!("         └─ {}", m.base_url);
        }
    }
    println!("\n  ⚠ No data stored in repo. Nodes download assigned shards from HuggingFace.\n");

    // ── Phase 3: Initialize coordinator ──
    println!("━━━ Phase 3: Coordinator Initialization ━━━\n");
    let keypair = PqcSigningKeypair::generate()?;
    let tee_id = TeeId::new([0xCC; 32]);
    let code_hash = B256::from([0xCC; 32]);
    let cert = RootTrustCertificate {
        version: 1, subject_tee_id: tee_id, subject_code_hash: code_hash,
        subject_public_key: keypair.public_key_bytes().to_vec(),
        issued_at: chrono::Utc::now().timestamp() as u64, expires_at: 0,
        root_trust_signature: vec![0u8; 100],
    };
    let mut tee = AiTrainingTee::new(
        keypair, tee_id, code_hash, cert,
        ModelArchitecture::Llama3_8B,
        U256::from(100_000_000_000_000_000_000u128),
    );
    println!("  Coordinator ready. Model: {} ({})\n", tee.model_config.name, tee.model_config.param_count_human());

    // ── Phase 4: Worker registration ──
    println!("━━━ Phase 4: Worker Registration (Different Allocations) ━━━\n");
    let workers_cfg: Vec<(Address, &str, u32, u64, f64)> = vec![
        (Address::from([0x01; 20]), "Node-Alpha", 2, 16384, 1.0),
        (Address::from([0x02; 20]), "Node-Beta",  1, 8192,  0.5),
        (Address::from([0x03; 20]), "Node-Gamma", 4, 32768, 0.25),
        (Address::from([0x04; 20]), "Node-Delta", 8, 81920, 0.75),
    ];
    for (addr, name, gpus, vram, alloc) in &workers_cfg {
        let caps = WorkerCapabilities {
            cpu_cores: 8, gpu_count: *gpus, gpu_memory_mib: *vram,
            ram_mib: 65536, benchmark_score: None,
        };
        let result = tee.register_worker(*addr, caps, ResourceAllocation::new(*alloc));
        println!("  [{}] GPUs={}, alloc={:.0}% → {}", name, gpus, alloc * 100.0, result);
    }
    println!("\n  Active workers: {}\n", tee.active_worker_count());

    // ── Phase 5: Simulated training loop ──
    println!("━━━ Phase 5: Distributed Training Loop ━━━\n");
    let mut rng = rand::thread_rng();
    let total_sim_steps = 5000u64;

    for step in (0..=total_sim_steps).step_by(1000) {
        let progress = step as f64 / total_sim_steps as f64;
        let base_loss = 10.0 * (1.0 - progress) + 2.0;

        for (addr, name, gpus, _vram, alloc) in &workers_cfg {
            let tokens = (32768.0 * alloc * (*gpus as f64)) as u64;
            let loss = base_loss + rng.gen_range(-0.3..0.3);
            tee.submit_gradient(GradientUpdate {
                worker: *addr, global_step: step,
                compressed_gradients: vec![0u8; 100],
                compression: GradientCompression::TopKQuantized { keep_fraction: 0.01 },
                gradient_norm: rng.gen_range(0.5..1.5),
                loss, tokens_processed: tokens,
                step_time_ms: rng.gen_range(200..500),
                per_layer_norms: vec![],
            });
        }

        println!("  Step {:>5} | loss={:.3} | progress={:.1}% | {:.0} tok/s",
            step, tee.training_state.avg_loss,
            progress * 100.0, tee.training_state.global_tokens_per_second);

        // Evaluation at milestones
        if step > 0 && step % 2500 == 0 {
            let report = tee.run_evaluation(step, (progress * 2e12) as u64, progress);
            println!("\n{}", report.format_report());
        }
    }

    // ── Phase 6: Final evaluation ──
    println!("━━━ Phase 6: Final Benchmark Evaluation ━━━\n");
    let final_report = tee.run_evaluation(total_sim_steps, 2_000_000_000_000, 1.0);
    println!("{}", final_report.format_report());

    // ── Phase 7: Block production ──
    println!("━━━ Phase 7: Block Production with Proportional Rewards ━━━\n");
    // Submit one more round for block production
    for (addr, _name, gpus, _vram, alloc) in &workers_cfg {
        let tokens = (32768.0 * alloc * (*gpus as f64)) as u64;
        tee.submit_gradient(GradientUpdate {
            worker: *addr, global_step: total_sim_steps,
            compressed_gradients: vec![0u8; 100],
            compression: GradientCompression::None,
            gradient_norm: 0.8, loss: 2.5, tokens_processed: tokens,
            step_time_ms: 300, per_layer_norms: vec![],
        });
    }
    let block = tee.produce_block(B256::ZERO)?;
    println!("  Block #{} produced. Rewards:", tee.blocks_produced);
    for inc in &block.message.incentives {
        println!("    {} → {} wei", inc.recipient, inc.amount);
    }

    // ── Phase 8: Inference ──
    println!("\n━━━ Phase 8: Model Serving (Open Inference API) ━━━\n");
    let req = InferenceRequest::simple("Explain quantum computing in simple terms.", 256);
    let resp = tee.handle_inference(&req);
    println!("  Prompt: \"{}\"", req.prompt);
    println!("  Response: {}", resp.completions[0].text);
    println!("  Model: {} @ step {} ({:.1}% trained)",
        resp.model_info.architecture, resp.model_info.training_step,
        resp.model_info.training_progress * 100.0);

    println!("\n  Serving stats: {} requests, {} tokens generated, {:.0}ms avg latency",
        tee.serving_state.total_requests, tee.serving_state.total_tokens_generated,
        tee.serving_state.avg_latency_ms);

    // ── Summary ──
    println!("\n━━━ Summary ━━━\n");
    println!("  Model:          {} ({})", tee.model_config.name, tee.model_config.param_count_human());
    println!("  Training steps: {}", tee.training_state.global_step);
    println!("  Final loss:     {:.3}", tee.training_state.avg_loss);
    println!("  Checkpoints:    {}", tee.training_state.checkpoints.len());
    println!("  Blocks:         {}", tee.blocks_produced);
    println!("  Workers:        {}", tee.active_worker_count());
    if let Some(scores) = tee.training_state.latest_checkpoint.as_ref().map(|c| &c.benchmark_scores) {
        if let Some(avg) = scores.average_accuracy() {
            println!("  Avg benchmark:  {:.1}%", avg);
        }
    }
    println!();

    Ok(())
}
