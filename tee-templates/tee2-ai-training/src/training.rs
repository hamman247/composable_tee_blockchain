//! Distributed training protocol for transformer models.
//!
//! Replaces the genetic algorithm with gradient-based distributed training
//! using ZeRO-3 data parallelism. Each worker node:
//!
//! 1. Holds 1/N of model parameters, gradients, and optimizer states
//! 2. Downloads and tokenizes its assigned data shards
//! 3. Computes forward/backward passes on micro-batches
//! 4. Compresses and submits gradients to the coordinator
//! 5. Receives aggregated gradients and applies optimizer step
//!
//! ## Consumer Hardware Support
//!
//! Designed for nodes with 64GB RAM and 2TB storage:
//! - ZeRO-3 partitions all state across nodes (linear memory scaling)
//! - Gradient compression reduces bandwidth by ~100×
//! - Streaming data loading: download → process → discard

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::model::{TransformerConfig, ModelCheckpoint, BenchmarkScores};
use crate::dataset::DatasetId;

// ────────────────────────────────────────────────────────────────────────
// Training Configuration
// ────────────────────────────────────────────────────────────────────────

/// Optimizer configuration (AdamW).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizerConfig {
    /// Learning rate.
    pub lr: f64,
    /// Beta1 (momentum decay).
    pub beta1: f64,
    /// Beta2 (variance decay).
    pub beta2: f64,
    /// Epsilon for numerical stability.
    pub eps: f64,
    /// Weight decay coefficient.
    pub weight_decay: f64,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            lr: 3e-4,
            beta1: 0.9,
            beta2: 0.95,
            eps: 1e-8,
            weight_decay: 0.1,
        }
    }
}

/// Learning rate scheduler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LrScheduler {
    /// Cosine decay with linear warmup.
    CosineWithWarmup {
        /// Number of warmup steps.
        warmup_steps: u64,
        /// Total training steps.
        total_steps: u64,
        /// Minimum learning rate (at end of cosine decay).
        min_lr: f64,
    },
    /// Constant learning rate.
    Constant,
}

impl LrScheduler {
    /// Compute the learning rate at a given step.
    pub fn get_lr(&self, base_lr: f64, step: u64) -> f64 {
        match self {
            Self::CosineWithWarmup { warmup_steps, total_steps, min_lr } => {
                if step < *warmup_steps {
                    // Linear warmup
                    base_lr * (step as f64 / *warmup_steps as f64)
                } else {
                    // Cosine decay
                    let progress = (step - warmup_steps) as f64
                        / (total_steps - warmup_steps) as f64;
                    let cosine = (1.0 + (std::f64::consts::PI * progress).cos()) / 2.0;
                    min_lr + (base_lr - min_lr) * cosine
                }
            }
            Self::Constant => base_lr,
        }
    }
}

/// Gradient compression method.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum GradientCompression {
    /// No compression (send full gradients).
    None,
    /// Top-K sparsification: only send the top K% of gradient values.
    /// The error (unsent values) is accumulated for the next round.
    TopK {
        /// Fraction of values to keep (e.g., 0.01 = top 1%).
        keep_fraction: f64,
    },
    /// Quantize gradients to INT8.
    QuantizeINT8,
    /// Combined: Top-K sparsification + INT8 quantization.
    TopKQuantized {
        keep_fraction: f64,
    },
}

impl GradientCompression {
    /// Estimated bandwidth reduction factor.
    pub fn reduction_factor(&self) -> f64 {
        match self {
            Self::None => 1.0,
            Self::TopK { keep_fraction } => 1.0 / keep_fraction,
            Self::QuantizeINT8 => 2.0, // BF16→INT8 = 2× reduction
            Self::TopKQuantized { keep_fraction } => 2.0 / keep_fraction,
        }
    }
}

/// Mixed precision training configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MixedPrecision {
    /// BF16 forward/backward, FP32 optimizer states.
    BF16,
    /// FP16 with loss scaling.
    FP16,
    /// Full FP32 (slow, high memory).
    FP32,
}

/// Complete training configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingConfig {
    /// Model architecture.
    pub model: TransformerConfig,
    /// Optimizer.
    pub optimizer: OptimizerConfig,
    /// Learning rate scheduler.
    pub scheduler: LrScheduler,
    /// Micro-batch size per node (number of sequences).
    pub micro_batch_size: u32,
    /// Gradient accumulation steps before an optimizer step.
    pub gradient_accumulation_steps: u32,
    /// Maximum sequence length.
    pub max_seq_len: u32,
    /// Gradient compression method.
    pub gradient_compression: GradientCompression,
    /// Mixed precision mode.
    pub mixed_precision: MixedPrecision,
    /// Max gradient norm for clipping.
    pub max_grad_norm: f64,
    /// How often to save a checkpoint (in steps).
    pub checkpoint_interval: u64,
    /// How often to run evaluation benchmarks (in steps).
    pub eval_interval: u64,
    /// How often to log training metrics (in steps).
    pub log_interval: u64,
    /// Datasets to use (with mix weights).
    pub dataset_mix: Vec<(DatasetId, f64)>,
    /// Total number of tokens to train on.
    pub total_training_tokens: u64,
}

impl TrainingConfig {
    /// Default config for training Llama-3 8B.
    pub fn default_8b(num_nodes: u32) -> Self {
        let model = TransformerConfig::llama3_8b();
        let micro_batch = 4u32;
        let grad_accum = 8u32;
        let global_batch_tokens = num_nodes as u64
            * micro_batch as u64
            * grad_accum as u64
            * 8192; // seq_len

        // ~2T tokens / global_batch_tokens = total steps
        let total_tokens = 2_000_000_000_000u64; // 2T tokens
        let total_steps = total_tokens / global_batch_tokens;

        Self {
            model,
            optimizer: OptimizerConfig {
                lr: 3e-4,
                ..Default::default()
            },
            scheduler: LrScheduler::CosineWithWarmup {
                warmup_steps: 2000,
                total_steps,
                min_lr: 3e-5,
            },
            micro_batch_size: micro_batch,
            gradient_accumulation_steps: grad_accum,
            max_seq_len: 8192,
            gradient_compression: GradientCompression::TopKQuantized { keep_fraction: 0.01 },
            mixed_precision: MixedPrecision::BF16,
            max_grad_norm: 1.0,
            checkpoint_interval: 1000,
            eval_interval: 1000,
            log_interval: 10,
            dataset_mix: vec![
                (DatasetId("fineweb".to_string()), 0.75),
                (DatasetId("the-stack-v2".to_string()), 0.10),
                (DatasetId("fineweb-edu".to_string()), 0.10),
                (DatasetId("open-web-math".to_string()), 0.05),
            ],
            total_training_tokens: total_tokens,
        }
    }

    /// Effective global batch size in tokens.
    pub fn global_batch_tokens(&self, num_nodes: u32) -> u64 {
        num_nodes as u64
            * self.micro_batch_size as u64
            * self.gradient_accumulation_steps as u64
            * self.max_seq_len as u64
    }

    /// Total training steps.
    pub fn total_steps(&self, num_nodes: u32) -> u64 {
        let batch_tokens = self.global_batch_tokens(num_nodes);
        if batch_tokens == 0 { return 0; }
        self.total_training_tokens / batch_tokens
    }

    /// Estimated training time in hours (given tokens/sec throughput per node).
    pub fn estimated_hours(&self, num_nodes: u32, tokens_per_sec_per_node: f64) -> f64 {
        let total_throughput = tokens_per_sec_per_node * num_nodes as f64;
        if total_throughput == 0.0 { return f64::INFINITY; }
        self.total_training_tokens as f64 / total_throughput / 3600.0
    }
}

// ────────────────────────────────────────────────────────────────────────
// Training Step Protocol
// ────────────────────────────────────────────────────────────────────────

/// A single training step assignment sent to a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingStep {
    /// Global training step number.
    pub global_step: u64,
    /// Data shard to read from.
    pub data_shard_id: String,
    /// Byte offset within the shard.
    pub data_offset: u64,
    /// Number of sequences to process in this micro-batch.
    pub micro_batch_size: u32,
    /// Sequence length.
    pub seq_len: u32,
    /// Current learning rate.
    pub learning_rate: f64,
    /// Whether to accumulate gradients (vs. apply optimizer step).
    pub accumulate_only: bool,
    /// Accumulation step index (0..gradient_accumulation_steps-1).
    pub accumulation_step: u32,
}

/// Compressed gradient update submitted by a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradientUpdate {
    /// Worker that computed these gradients.
    pub worker: Address,
    /// Global step this gradient corresponds to.
    pub global_step: u64,
    /// Compressed gradient data.
    /// Format depends on compression method:
    /// - None: raw BF16 bytes
    /// - TopK: sparse representation (indices + values)
    /// - INT8: quantized with scale factors
    pub compressed_gradients: Vec<u8>,
    /// Compression method used.
    pub compression: GradientCompression,
    /// L2 norm of the full (uncompressed) gradient.
    pub gradient_norm: f64,
    /// Training loss for this micro-batch.
    pub loss: f64,
    /// Number of tokens processed.
    pub tokens_processed: u64,
    /// Wall-clock time for this step (ms).
    pub step_time_ms: u64,
    /// Per-layer gradient norms (for monitoring).
    pub per_layer_norms: Vec<f64>,
}

/// Aggregated gradient result sent back to workers after AllReduce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedGradients {
    /// Global step.
    pub global_step: u64,
    /// Aggregated gradient data (average across all workers).
    pub gradients: Vec<u8>,
    /// Number of workers that contributed.
    pub num_contributors: u32,
    /// Average loss across all workers.
    pub avg_loss: f64,
    /// Current learning rate.
    pub learning_rate: f64,
    /// Whether to apply optimizer step now.
    pub apply_optimizer: bool,
}

// ────────────────────────────────────────────────────────────────────────
// Training Metrics
// ────────────────────────────────────────────────────────────────────────

/// Per-step training metrics reported by each worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetrics {
    /// Worker address.
    pub worker: Address,
    /// Global training step.
    pub global_step: u64,
    /// Training loss (cross-entropy).
    pub loss: f64,
    /// Current learning rate.
    pub learning_rate: f64,
    /// Gradient norm (after clipping).
    pub gradient_norm: f64,
    /// Tokens processed per second by this worker.
    pub tokens_per_second: f64,
    /// Total tokens processed by this worker so far.
    pub tokens_processed_total: u64,
    /// GPU memory usage in bytes (if available).
    pub gpu_memory_bytes: Option<u64>,
    /// GPU utilization (0.0 - 1.0).
    pub gpu_utilization: f64,
}

/// Global training state maintained by the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingState {
    /// Current global training step.
    pub global_step: u64,
    /// Total tokens processed across all workers.
    pub total_tokens_processed: u64,
    /// Target total tokens.
    pub total_training_tokens: u64,
    /// Training progress (0.0 - 1.0).
    pub progress: f64,
    /// Current average loss across all workers.
    pub avg_loss: f64,
    /// Loss history (sampled, for tracking convergence).
    pub loss_history: Vec<(u64, f64)>, // (step, loss)
    /// Current learning rate.
    pub learning_rate: f64,
    /// Number of active workers.
    pub active_workers: u32,
    /// Tokens per second (global throughput).
    pub global_tokens_per_second: f64,
    /// Estimated time remaining (seconds).
    pub eta_seconds: f64,
    /// Latest checkpoint.
    pub latest_checkpoint: Option<ModelCheckpoint>,
    /// All saved checkpoints.
    pub checkpoints: Vec<ModelCheckpoint>,
}

impl TrainingState {
    pub fn new(total_training_tokens: u64) -> Self {
        Self {
            global_step: 0,
            total_tokens_processed: 0,
            total_training_tokens,
            progress: 0.0,
            avg_loss: f64::NAN,
            loss_history: Vec::new(),
            learning_rate: 0.0,
            active_workers: 0,
            global_tokens_per_second: 0.0,
            eta_seconds: f64::INFINITY,
            latest_checkpoint: None,
            checkpoints: Vec::new(),
        }
    }

    /// Update state with a batch of worker metrics.
    pub fn update(&mut self, metrics: &[TrainingMetrics], lr: f64) {
        if metrics.is_empty() { return; }

        self.global_step = metrics.iter().map(|m| m.global_step).max().unwrap_or(0);
        self.avg_loss = metrics.iter().map(|m| m.loss).sum::<f64>() / metrics.len() as f64;
        self.learning_rate = lr;
        self.active_workers = metrics.len() as u32;
        self.global_tokens_per_second = metrics.iter().map(|m| m.tokens_per_second).sum();

        self.total_tokens_processed = metrics.iter()
            .map(|m| m.tokens_processed_total)
            .sum();

        self.progress = if self.total_training_tokens > 0 {
            self.total_tokens_processed as f64 / self.total_training_tokens as f64
        } else { 0.0 };

        let remaining_tokens = self.total_training_tokens.saturating_sub(self.total_tokens_processed);
        self.eta_seconds = if self.global_tokens_per_second > 0.0 {
            remaining_tokens as f64 / self.global_tokens_per_second
        } else { f64::INFINITY };

        // Sample loss history (keep last 1000 points)
        self.loss_history.push((self.global_step, self.avg_loss));
        if self.loss_history.len() > 1000 {
            self.loss_history.remove(0);
        }
    }

    /// Save a checkpoint.
    pub fn save_checkpoint(&mut self, config: &TransformerConfig, scores: BenchmarkScores) {
        let checkpoint = ModelCheckpoint {
            config: config.clone(),
            global_step: self.global_step,
            tokens_processed: self.total_tokens_processed,
            weights_hash: format!("sha3_{:016x}", self.global_step),
            training_loss: self.avg_loss,
            validation_loss: scores.perplexity,
            benchmark_scores: scores,
            num_contributing_nodes: self.active_workers,
            saved_at: chrono::Utc::now().timestamp() as u64,
            weight_shard_urls: Vec::new(),
            num_weight_shards: self.active_workers,
        };
        self.latest_checkpoint = Some(checkpoint.clone());
        self.checkpoints.push(checkpoint);
    }

    /// Training progress as a human-readable string.
    pub fn progress_summary(&self) -> String {
        let pct = self.progress * 100.0;
        let eta_hours = self.eta_seconds / 3600.0;
        format!(
            "Step {} | Loss: {:.4} | LR: {:.2e} | Progress: {:.2}% | {:.1}T/{:.1}T tokens | {:.0} tok/s | ETA: {:.1}h",
            self.global_step, self.avg_loss, self.learning_rate, pct,
            self.total_tokens_processed as f64 / 1e12,
            self.total_training_tokens as f64 / 1e12,
            self.global_tokens_per_second, eta_hours
        )
    }
}

// ────────────────────────────────────────────────────────────────────────
// Gradient Aggregator
// ────────────────────────────────────────────────────────────────────────

/// Simulated AllReduce gradient aggregator.
///
/// In production, this would use NCCL or a custom ring-allreduce implementation.
/// Here we aggregate in the coordinator (star topology) which works for the
/// coordinator-based architecture where the TEE is the trusted aggregation point.
pub struct GradientAggregator {
    /// Pending gradients for the current step.
    pending: HashMap<Address, GradientUpdate>,
    /// Number of workers expected to contribute.
    expected_workers: u32,
    /// Current step being aggregated.
    current_step: u64,
}

impl GradientAggregator {
    pub fn new(expected_workers: u32) -> Self {
        Self {
            pending: HashMap::new(),
            expected_workers,
            current_step: 0,
        }
    }

    /// Submit a gradient update from a worker.
    /// Returns Some(AggregatedGradients) when all workers have submitted.
    pub fn submit(&mut self, update: GradientUpdate) -> Option<AggregatedGradients> {
        self.current_step = update.global_step;
        self.pending.insert(update.worker, update);

        if self.pending.len() as u32 >= self.expected_workers {
            Some(self.aggregate())
        } else {
            None
        }
    }

    /// Aggregate all pending gradients (AllReduce: average).
    fn aggregate(&mut self) -> AggregatedGradients {
        let num = self.pending.len() as f64;
        let avg_loss = self.pending.values().map(|u| u.loss).sum::<f64>() / num;

        // In production: decompress each worker's gradients, average element-wise,
        // re-compress, and distribute. Here we produce a symbolic result.
        let total_bytes: usize = self.pending.values()
            .map(|u| u.compressed_gradients.len())
            .sum();

        let result = AggregatedGradients {
            global_step: self.current_step,
            gradients: vec![0u8; total_bytes / self.pending.len()], // Symbolic
            num_contributors: self.pending.len() as u32,
            avg_loss,
            learning_rate: 0.0, // Set by caller
            apply_optimizer: true,
        };

        self.pending.clear();
        result
    }

    /// Number of gradients received so far for the current step.
    pub fn received_count(&self) -> u32 {
        self.pending.len() as u32
    }

    /// Update expected worker count (when workers join/leave).
    pub fn set_expected_workers(&mut self, count: u32) {
        self.expected_workers = count;
    }
}

// ────────────────────────────────────────────────────────────────────────
// Per-Worker Reward Calculation
// ────────────────────────────────────────────────────────────────────────

/// Reward breakdown for a single worker in a training round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerReward {
    /// Worker address.
    pub worker: Address,
    /// Tokens processed in this round.
    pub tokens_processed: u64,
    /// Proportion of total tokens (0.0 - 1.0).
    pub token_proportion: f64,
    /// Number of gradient submissions.
    pub gradient_submissions: u64,
    /// Average gradient quality (norm within expected range = 1.0).
    pub gradient_quality: f64,
    /// Final reward proportion (tokens × quality).
    pub reward_proportion: f64,
}

/// Calculate proportional rewards for all workers based on actual compute.
pub fn calculate_rewards(metrics: &[TrainingMetrics]) -> Vec<WorkerReward> {
    let total_tokens: u64 = metrics.iter().map(|m| m.tokens_processed_total).sum();
    if total_tokens == 0 { return vec![]; }

    metrics.iter().map(|m| {
        let token_prop = m.tokens_processed_total as f64 / total_tokens as f64;
        // Gradient quality: penalize workers with anomalous gradient norms
        // (too high = diverging, too low = dead parameters)
        let quality = if m.gradient_norm > 0.0 && m.gradient_norm < 100.0 {
            1.0
        } else {
            0.5 // Reduced reward for suspicious gradients
        };
        let reward_prop = token_prop * quality;

        WorkerReward {
            worker: m.worker,
            tokens_processed: m.tokens_processed_total,
            token_proportion: token_prop,
            gradient_submissions: 1,
            gradient_quality: quality,
            reward_proportion: reward_prop,
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TransformerConfig;

    #[test]
    fn test_lr_scheduler_warmup() {
        let scheduler = LrScheduler::CosineWithWarmup {
            warmup_steps: 1000,
            total_steps: 100_000,
            min_lr: 3e-5,
        };
        let base_lr = 3e-4;

        // At step 0: LR = 0
        assert!((scheduler.get_lr(base_lr, 0) - 0.0).abs() < 1e-10);
        // At step 500: LR = 50% of base
        assert!((scheduler.get_lr(base_lr, 500) - 1.5e-4).abs() < 1e-10);
        // At step 1000: LR = base
        assert!((scheduler.get_lr(base_lr, 1000) - base_lr).abs() < 1e-10);
        // At end: LR ≈ min_lr
        assert!((scheduler.get_lr(base_lr, 100_000) - 3e-5).abs() < 1e-6);
    }

    #[test]
    fn test_gradient_compression_reduction() {
        let topk = GradientCompression::TopK { keep_fraction: 0.01 };
        assert!((topk.reduction_factor() - 100.0).abs() < 0.1);

        let combined = GradientCompression::TopKQuantized { keep_fraction: 0.01 };
        assert!((combined.reduction_factor() - 200.0).abs() < 0.1);
    }

    #[test]
    fn test_training_config_batch_size() {
        let config = TrainingConfig::default_8b(10);
        let batch_tokens = config.global_batch_tokens(10);
        // 10 nodes × 4 micro-batch × 8 accum × 8192 seq_len
        assert_eq!(batch_tokens, 10 * 4 * 8 * 8192);
        println!("Global batch: {} tokens ({:.1}M)", batch_tokens, batch_tokens as f64 / 1e6);
    }

    #[test]
    fn test_training_state_update() {
        let mut state = TrainingState::new(1_000_000_000_000); // 1T tokens
        let metrics = vec![
            TrainingMetrics {
                worker: Address::from([0x01; 20]),
                global_step: 100,
                loss: 3.5,
                learning_rate: 3e-4,
                gradient_norm: 0.8,
                tokens_per_second: 50_000.0,
                tokens_processed_total: 500_000_000,
                gpu_memory_bytes: None,
                gpu_utilization: 0.95,
            },
            TrainingMetrics {
                worker: Address::from([0x02; 20]),
                global_step: 100,
                loss: 3.3,
                learning_rate: 3e-4,
                gradient_norm: 0.9,
                tokens_per_second: 45_000.0,
                tokens_processed_total: 450_000_000,
                gpu_memory_bytes: None,
                gpu_utilization: 0.90,
            },
        ];

        state.update(&metrics, 3e-4);
        assert_eq!(state.global_step, 100);
        assert!((state.avg_loss - 3.4).abs() < 0.01);
        assert_eq!(state.active_workers, 2);
        assert!(state.global_tokens_per_second > 90_000.0);
        assert!(state.progress > 0.0);
    }

    #[test]
    fn test_gradient_aggregator() {
        let mut agg = GradientAggregator::new(3);

        let make_update = |addr_byte: u8, loss: f64| GradientUpdate {
            worker: Address::from([addr_byte; 20]),
            global_step: 42,
            compressed_gradients: vec![0u8; 1000],
            compression: GradientCompression::None,
            gradient_norm: 1.0,
            loss,
            tokens_processed: 32768,
            step_time_ms: 500,
            per_layer_norms: vec![],
        };

        // First two: no result yet
        assert!(agg.submit(make_update(1, 3.0)).is_none());
        assert!(agg.submit(make_update(2, 4.0)).is_none());
        // Third: triggers aggregation
        let result = agg.submit(make_update(3, 5.0));
        assert!(result.is_some());
        let agg_result = result.unwrap();
        assert_eq!(agg_result.num_contributors, 3);
        assert!((agg_result.avg_loss - 4.0).abs() < 0.01);
    }

    #[test]
    fn test_reward_calculation() {
        let metrics = vec![
            TrainingMetrics {
                worker: Address::from([0x01; 20]),
                global_step: 100, loss: 3.0, learning_rate: 3e-4,
                gradient_norm: 1.0, tokens_per_second: 50_000.0,
                tokens_processed_total: 1_000_000, // 1M tokens
                gpu_memory_bytes: None, gpu_utilization: 0.95,
            },
            TrainingMetrics {
                worker: Address::from([0x02; 20]),
                global_step: 100, loss: 3.0, learning_rate: 3e-4,
                gradient_norm: 1.0, tokens_per_second: 25_000.0,
                tokens_processed_total: 500_000, // 0.5M tokens (half)
                gpu_memory_bytes: None, gpu_utilization: 0.90,
            },
        ];

        let rewards = calculate_rewards(&metrics);
        assert_eq!(rewards.len(), 2);
        // Worker 1 processed 2× more tokens, should get 2× the reward
        let ratio = rewards[0].reward_proportion / rewards[1].reward_proportion;
        assert!((ratio - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_estimated_training_time() {
        let config = TrainingConfig::default_8b(100);
        // 100 nodes, each doing ~50K tokens/sec
        let hours = config.estimated_hours(100, 50_000.0);
        println!("8B model, 100 nodes @ 50K tok/s: {:.0} hours ({:.1} days)",
            hours, hours / 24.0);
        // 2T tokens / (100 × 50K) = 400K seconds ≈ 111 hours ≈ 4.6 days
        assert!(hours > 50.0 && hours < 200.0);
    }
}
