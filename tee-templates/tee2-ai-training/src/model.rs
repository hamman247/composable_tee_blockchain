//! Transformer model architecture definitions for distributed training.
//!
//! Defines Llama-3 family architectures with exact parameter counts and
//! memory budget calculations for ZeRO-3 distributed training across
//! consumer hardware nodes.
//!
//! ## No weights stored here
//!
//! This module contains only **architecture configs** — no model weights.
//! Weights are distributed across worker nodes via ZeRO-3 sharding and
//! checkpointed to shared storage (IPFS / HuggingFace Hub).

use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────
// Model Architecture
// ────────────────────────────────────────────────────────────────────────

/// Supported model architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelArchitecture {
    /// ~8B parameters, trainable on 4-10 consumer nodes
    Llama3_8B,
    /// ~70B parameters, needs ~100+ consumer nodes
    Llama3_70B,
    /// ~405B parameters, needs ~500+ consumer nodes
    Llama3_405B,
    /// Custom architecture with user-defined config
    Custom,
}

impl std::fmt::Display for ModelArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Llama3_8B => write!(f, "Llama-3-8B"),
            Self::Llama3_70B => write!(f, "Llama-3-70B"),
            Self::Llama3_405B => write!(f, "Llama-3-405B"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// Activation function used in FFN layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Activation {
    /// SwiGLU: x * SiLU(gate(x)), used by Llama-3
    SwiGLU,
    /// Standard GELU
    GELU,
    /// ReLU (legacy)
    ReLU,
}

/// Normalization type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormType {
    /// RMSNorm (used by Llama-3) — faster than LayerNorm
    RMSNorm,
    /// Standard LayerNorm
    LayerNorm,
}

/// Positional embedding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PositionalEmbedding {
    /// Rotary Position Embeddings (RoPE), used by Llama-3
    RoPE { theta: u64 },
    /// Absolute learned embeddings (GPT-2 style)
    Learned,
    /// ALiBi (attention with linear biases)
    ALiBi,
}

/// Complete transformer configuration.
///
/// All values match published Llama-3 specifications from Meta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformerConfig {
    /// Architecture identifier.
    pub architecture: ModelArchitecture,
    /// Human-readable name.
    pub name: String,

    // ── Dimensions ──
    /// Number of transformer layers (decoder blocks).
    pub num_layers: u32,
    /// Hidden dimension (d_model).
    pub hidden_dim: u32,
    /// Number of attention heads (queries).
    pub num_heads: u32,
    /// Number of key/value heads (for Grouped-Query Attention).
    /// When num_kv_heads < num_heads, GQA is used.
    pub num_kv_heads: u32,
    /// FFN intermediate dimension.
    pub ffn_hidden_dim: u32,
    /// Vocabulary size.
    pub vocab_size: u32,

    // ── Sequence ──
    /// Maximum sequence length (context window).
    pub max_seq_len: u32,

    // ── Architecture choices ──
    /// Activation function in FFN layers.
    pub activation: Activation,
    /// Normalization type.
    pub norm_type: NormType,
    /// Positional embedding type.
    pub positional_embedding: PositionalEmbedding,
    /// Whether to tie input and output embeddings.
    pub tie_embeddings: bool,

    // ── Precision ──
    /// Bytes per parameter during training (2 for BF16, 4 for FP32).
    pub param_dtype_bytes: u8,
}

impl TransformerConfig {
    /// Llama-3 8B configuration (matches Meta's published specs).
    pub fn llama3_8b() -> Self {
        Self {
            architecture: ModelArchitecture::Llama3_8B,
            name: "Llama-3-8B".to_string(),
            num_layers: 32,
            hidden_dim: 4096,
            num_heads: 32,
            num_kv_heads: 8,
            ffn_hidden_dim: 14336,
            vocab_size: 128256,
            max_seq_len: 8192,
            activation: Activation::SwiGLU,
            norm_type: NormType::RMSNorm,
            positional_embedding: PositionalEmbedding::RoPE { theta: 500_000 },
            tie_embeddings: false,
            param_dtype_bytes: 2, // BF16
        }
    }

    /// Llama-3 70B configuration.
    pub fn llama3_70b() -> Self {
        Self {
            architecture: ModelArchitecture::Llama3_70B,
            name: "Llama-3-70B".to_string(),
            num_layers: 80,
            hidden_dim: 8192,
            num_heads: 64,
            num_kv_heads: 8,
            ffn_hidden_dim: 28672,
            vocab_size: 128256,
            max_seq_len: 8192,
            activation: Activation::SwiGLU,
            norm_type: NormType::RMSNorm,
            positional_embedding: PositionalEmbedding::RoPE { theta: 500_000 },
            tie_embeddings: false,
            param_dtype_bytes: 2,
        }
    }

    /// Llama-3 405B configuration.
    pub fn llama3_405b() -> Self {
        Self {
            architecture: ModelArchitecture::Llama3_405B,
            name: "Llama-3-405B".to_string(),
            num_layers: 126,
            hidden_dim: 16384,
            num_heads: 128,
            num_kv_heads: 8,
            ffn_hidden_dim: 53248,
            vocab_size: 128256,
            max_seq_len: 8192,
            activation: Activation::SwiGLU,
            norm_type: NormType::RMSNorm,
            positional_embedding: PositionalEmbedding::RoPE { theta: 500_000 },
            tie_embeddings: false,
            param_dtype_bytes: 2,
        }
    }

    /// Get config for a given architecture.
    pub fn for_architecture(arch: ModelArchitecture) -> Self {
        match arch {
            ModelArchitecture::Llama3_8B => Self::llama3_8b(),
            ModelArchitecture::Llama3_70B => Self::llama3_70b(),
            ModelArchitecture::Llama3_405B => Self::llama3_405b(),
            ModelArchitecture::Custom => Self::llama3_8b(), // Default to 8B
        }
    }

    /// Head dimension (hidden_dim / num_heads).
    pub fn head_dim(&self) -> u32 {
        self.hidden_dim / self.num_heads
    }

    /// Total parameter count (approximate, matches published numbers).
    pub fn param_count(&self) -> u64 {
        let h = self.hidden_dim as u64;
        let l = self.num_layers as u64;
        let v = self.vocab_size as u64;
        let ffn = self.ffn_hidden_dim as u64;
        let kv = self.num_kv_heads as u64;
        let head_d = self.head_dim() as u64;

        // Embedding: vocab × hidden
        let embedding = v * h;
        // Output projection (if not tied): vocab × hidden
        let output = if self.tie_embeddings { 0 } else { v * h };

        // Per-layer parameters:
        // Q projection: hidden × hidden
        let q_proj = h * h;
        // K projection: hidden × (kv_heads × head_dim)
        let k_proj = h * (kv * head_d);
        // V projection: same as K
        let v_proj = h * (kv * head_d);
        // O projection: hidden × hidden
        let o_proj = h * h;
        // Attention total
        let attn = q_proj + k_proj + v_proj + o_proj;

        // FFN (SwiGLU has 3 projections: gate, up, down)
        let ffn_params = if self.activation == Activation::SwiGLU {
            3 * h * ffn // gate_proj + up_proj + down_proj
        } else {
            2 * h * ffn // up_proj + down_proj
        };

        // RMSNorm: 2 per layer (attn + ffn) × hidden
        let norm = 2 * h;

        let per_layer = attn + ffn_params + norm;

        // Final norm
        let final_norm = h;

        embedding + output + (l * per_layer) + final_norm
    }

    /// Total model size in bytes (parameters × dtype bytes).
    pub fn model_size_bytes(&self) -> u64 {
        self.param_count() * self.param_dtype_bytes as u64
    }

    /// Human-readable model size.
    pub fn model_size_human(&self) -> String {
        let bytes = self.model_size_bytes();
        if bytes >= 1_000_000_000 {
            format!("{:.1} GB", bytes as f64 / 1e9)
        } else {
            format!("{:.1} MB", bytes as f64 / 1e6)
        }
    }

    /// Human-readable parameter count.
    pub fn param_count_human(&self) -> String {
        let p = self.param_count();
        if p >= 1_000_000_000 {
            format!("{:.1}B", p as f64 / 1e9)
        } else {
            format!("{:.1}M", p as f64 / 1e6)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// ZeRO-3 Memory Budget
// ────────────────────────────────────────────────────────────────────────

/// Memory budget for a single node under ZeRO-3 sharding.
///
/// ZeRO-3 partitions parameters, gradients, AND optimizer states across
/// all nodes, so each node holds only `1/N` of each.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBudget {
    /// Total parameter count.
    pub total_params: u64,
    /// Number of nodes in the cluster.
    pub num_nodes: u32,
    /// Bytes per parameter (dtype).
    pub param_dtype_bytes: u8,

    // ── Per-node breakdown ──
    /// Parameter shard size (bytes) — 1/N of total params.
    pub param_shard_bytes: u64,
    /// Gradient shard size (bytes) — same dtype as params.
    pub gradient_shard_bytes: u64,
    /// Optimizer state shard size (bytes).
    /// AdamW stores 2 states per param (momentum + variance) in FP32.
    pub optimizer_shard_bytes: u64,
    /// Activation memory estimate (bytes) for one micro-batch.
    pub activation_bytes: u64,
    /// Total per-node memory (bytes).
    pub total_per_node_bytes: u64,
    /// Total per-node memory (GB).
    pub total_per_node_gb: f64,
    /// Whether this fits in the given RAM budget.
    pub fits_in_budget: bool,
    /// RAM budget used for the calculation (bytes).
    pub ram_budget_bytes: u64,
}

impl MemoryBudget {
    /// Calculate the memory budget for a given config and node count.
    ///
    /// `ram_budget_gb`: Available RAM per node in GB (e.g., 64).
    /// `micro_batch_size`: Number of sequences per micro-batch.
    /// `seq_len`: Sequence length for activation estimate.
    pub fn calculate(
        config: &TransformerConfig,
        num_nodes: u32,
        ram_budget_gb: f64,
        micro_batch_size: u32,
        seq_len: u32,
    ) -> Self {
        let total_params = config.param_count();
        let n = num_nodes as u64;
        let dtype = config.param_dtype_bytes as u64;
        let ram_budget_bytes = (ram_budget_gb * 1e9) as u64;

        // ZeRO-3: each node holds 1/N of params, grads, and optimizer states
        let param_shard_bytes = (total_params * dtype) / n;
        let gradient_shard_bytes = param_shard_bytes; // Same dtype as params

        // AdamW optimizer: 2 FP32 states per param (momentum + variance)
        // But only 1/N of them per node
        let optimizer_shard_bytes = (total_params * 4 * 2) / n; // FP32 × 2 states

        // Activation memory estimate (rough):
        // Per layer: 2 × batch × seq × hidden × dtype (for attention + FFN intermediates)
        // Plus KV cache: 2 × batch × seq × kv_heads × head_dim × dtype × num_layers
        let h = config.hidden_dim as u64;
        let l = config.num_layers as u64;
        let b = micro_batch_size as u64;
        let s = seq_len as u64;

        // Simplified activation estimate (per-layer activations are recomputed
        // in gradient checkpointing mode, so we only need ~2 layers worth)
        let activation_bytes = 2 * b * s * h * dtype * 2; // ×2 for intermediates

        let total_per_node_bytes = param_shard_bytes
            + gradient_shard_bytes
            + optimizer_shard_bytes
            + activation_bytes;

        let total_per_node_gb = total_per_node_bytes as f64 / 1e9;

        Self {
            total_params,
            num_nodes,
            param_dtype_bytes: config.param_dtype_bytes,
            param_shard_bytes,
            gradient_shard_bytes,
            optimizer_shard_bytes,
            activation_bytes,
            total_per_node_bytes,
            total_per_node_gb,
            fits_in_budget: total_per_node_bytes <= ram_budget_bytes,
            ram_budget_bytes,
        }
    }

    /// Minimum number of nodes needed to fit within the RAM budget.
    pub fn min_nodes_for_budget(
        config: &TransformerConfig,
        ram_budget_gb: f64,
        micro_batch_size: u32,
        seq_len: u32,
    ) -> u32 {
        for n in 1..100_000 {
            let budget = Self::calculate(config, n, ram_budget_gb, micro_batch_size, seq_len);
            if budget.fits_in_budget {
                return n;
            }
        }
        100_000
    }
}

// ────────────────────────────────────────────────────────────────────────
// Model Checkpoint
// ────────────────────────────────────────────────────────────────────────

/// A snapshot of the model at a particular training step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCheckpoint {
    /// Architecture config.
    pub config: TransformerConfig,
    /// Global training step when this checkpoint was saved.
    pub global_step: u64,
    /// Total tokens processed up to this point.
    pub tokens_processed: u64,
    /// SHA3-256 hash of all model weights (for integrity verification).
    pub weights_hash: String,
    /// Training loss at this step.
    pub training_loss: f64,
    /// Validation loss (perplexity on held-out data).
    pub validation_loss: Option<f64>,
    /// Benchmark scores at this checkpoint.
    pub benchmark_scores: BenchmarkScores,
    /// Number of nodes that contributed to training up to this point.
    pub num_contributing_nodes: u32,
    /// Timestamp when checkpoint was saved.
    pub saved_at: u64,
    /// URLs where weight shards can be downloaded.
    pub weight_shard_urls: Vec<String>,
    /// Number of weight shards (= number of ZeRO-3 partitions at save time).
    pub num_weight_shards: u32,
}

/// Aggregated benchmark scores for a checkpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkScores {
    /// Perplexity on held-out validation set (lower = better).
    pub perplexity: Option<f64>,
    /// MMLU 5-shot accuracy (0-100%).
    pub mmlu: Option<f64>,
    /// HumanEval pass@1 (0-100%).
    pub humaneval: Option<f64>,
    /// GSM8K accuracy (0-100%).
    pub gsm8k: Option<f64>,
    /// ARC-Challenge accuracy (0-100%).
    pub arc_challenge: Option<f64>,
    /// TruthfulQA MC accuracy (0-100%).
    pub truthfulqa: Option<f64>,
    /// MATH accuracy (0-100%).
    pub math: Option<f64>,
    /// WinoGrande accuracy (0-100%).
    pub winogrande: Option<f64>,
}

impl BenchmarkScores {
    /// Average across all available scores (excluding perplexity).
    pub fn average_accuracy(&self) -> Option<f64> {
        let scores: Vec<f64> = [
            self.mmlu, self.humaneval, self.gsm8k, self.arc_challenge,
            self.truthfulqa, self.math, self.winogrande,
        ].iter().filter_map(|s| *s).collect();

        if scores.is_empty() { None } else { Some(scores.iter().sum::<f64>() / scores.len() as f64) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llama3_8b_param_count() {
        let config = TransformerConfig::llama3_8b();
        let params = config.param_count();
        // Llama-3 8B has ~8.03B parameters
        assert!(params > 7_000_000_000, "8B model should have >7B params, got {}", params);
        assert!(params < 9_000_000_000, "8B model should have <9B params, got {}", params);
        println!("Llama-3-8B: {} params ({})", params, config.param_count_human());
    }

    #[test]
    fn test_llama3_70b_param_count() {
        let config = TransformerConfig::llama3_70b();
        let params = config.param_count();
        assert!(params > 60_000_000_000, "70B model should have >60B params, got {}", params);
        assert!(params < 80_000_000_000, "70B model should have <80B params, got {}", params);
        println!("Llama-3-70B: {} params ({})", params, config.param_count_human());
    }

    #[test]
    fn test_llama3_405b_param_count() {
        let config = TransformerConfig::llama3_405b();
        let params = config.param_count();
        assert!(params > 350_000_000_000, "405B model should have >350B params, got {}", params);
        assert!(params < 450_000_000_000, "405B model should have <450B params, got {}", params);
        println!("Llama-3-405B: {} params ({})", params, config.param_count_human());
    }

    #[test]
    fn test_memory_budget_8b_10_nodes() {
        let config = TransformerConfig::llama3_8b();
        let budget = MemoryBudget::calculate(&config, 10, 64.0, 4, 8192);
        println!("8B model, 10 nodes: {:.2} GB/node", budget.total_per_node_gb);
        println!("  params: {:.2} GB", budget.param_shard_bytes as f64 / 1e9);
        println!("  grads:  {:.2} GB", budget.gradient_shard_bytes as f64 / 1e9);
        println!("  optim:  {:.2} GB", budget.optimizer_shard_bytes as f64 / 1e9);
        println!("  activ:  {:.2} GB", budget.activation_bytes as f64 / 1e9);
        assert!(budget.fits_in_budget, "8B with 10 nodes should fit in 64GB");
        assert!(budget.total_per_node_gb < 20.0, "Should use <20GB per node");
    }

    #[test]
    fn test_memory_budget_70b_min_nodes() {
        let config = TransformerConfig::llama3_70b();
        let min = MemoryBudget::min_nodes_for_budget(&config, 64.0, 2, 4096);
        println!("70B model minimum nodes for 64GB RAM: {}", min);
        assert!(min >= 10, "70B should need at least 10 nodes");
        assert!(min <= 200, "70B shouldn't need more than 200 nodes for 64GB");
    }

    #[test]
    fn test_model_size_human() {
        let config = TransformerConfig::llama3_8b();
        let size = config.model_size_human();
        assert!(size.contains("GB"), "8B model size should be in GB: {}", size);
    }

    #[test]
    fn test_benchmark_scores_average() {
        let scores = BenchmarkScores {
            perplexity: Some(3.0),
            mmlu: Some(85.0),
            humaneval: Some(70.0),
            gsm8k: Some(90.0),
            arc_challenge: None,
            truthfulqa: None,
            math: None,
            winogrande: None,
        };
        let avg = scores.average_accuracy().unwrap();
        assert!((avg - 81.67).abs() < 0.1);
    }
}
