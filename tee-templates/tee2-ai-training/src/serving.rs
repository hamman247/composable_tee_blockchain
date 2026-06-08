//! Model serving and inference API.
//!
//! Any operational node running the TEE can serve inference queries on
//! the current (or any checkpointed) model state. The API is open —
//! anyone can query the model.
//!
//! ## Architecture
//!
//! Since model weights are distributed across nodes via ZeRO-3, inference
//! can work in two modes:
//!
//! 1. **Gathered mode**: A single node collects all weight shards and runs
//!    inference locally. Suitable for small models (8B fits in 64GB).
//!
//! 2. **Pipeline mode**: Inference is routed through a pipeline of nodes,
//!    each running their portion of the model. Required for 70B+ models
//!    that don't fit in a single node's memory.
//!
//! ## Access
//!
//! Model weights, configs, and tokenizer are downloadable by anyone.
//! Inference queries are open and free (rate-limited per IP to prevent abuse).

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::model::{TransformerConfig, ModelCheckpoint, BenchmarkScores};
use crate::training::TrainingState;

// ────────────────────────────────────────────────────────────────────────
// Inference API
// ────────────────────────────────────────────────────────────────────────

/// Sampling parameters for text generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingParams {
    /// Temperature (0.0 = greedy, 1.0 = default, >1.0 = creative).
    pub temperature: f64,
    /// Top-p (nucleus) sampling threshold.
    pub top_p: f64,
    /// Top-k sampling (0 = disabled).
    pub top_k: u32,
    /// Repetition penalty (1.0 = disabled).
    pub repetition_penalty: f64,
    /// Frequency penalty (0.0 = disabled).
    pub frequency_penalty: f64,
    /// Presence penalty (0.0 = disabled).
    pub presence_penalty: f64,
}

impl Default for SamplingParams {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            top_p: 0.9,
            top_k: 0,
            repetition_penalty: 1.0,
            frequency_penalty: 0.0,
            presence_penalty: 0.0,
        }
    }
}

/// Request to generate text from the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Input prompt text.
    pub prompt: String,
    /// Maximum number of tokens to generate.
    pub max_tokens: u32,
    /// Sampling parameters.
    pub sampling: SamplingParams,
    /// Optional: specific checkpoint to use (None = latest).
    pub checkpoint_step: Option<u64>,
    /// Whether to return token-level log probabilities.
    pub return_logprobs: bool,
    /// Number of completions to generate.
    pub n: u32,
    /// Stop sequences (generation stops when any of these are produced).
    pub stop: Vec<String>,
}

impl InferenceRequest {
    /// Simple request with defaults.
    pub fn simple(prompt: impl Into<String>, max_tokens: u32) -> Self {
        Self {
            prompt: prompt.into(),
            max_tokens,
            sampling: SamplingParams::default(),
            checkpoint_step: None,
            return_logprobs: false,
            n: 1,
            stop: vec![],
        }
    }
}

/// Response from text generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Generated completions.
    pub completions: Vec<Completion>,
    /// Model version info.
    pub model_info: ModelVersion,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
    /// Tokens generated.
    pub tokens_generated: u32,
    /// Tokens in the prompt.
    pub prompt_tokens: u32,
}

/// A single completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    /// Generated text.
    pub text: String,
    /// Finish reason.
    pub finish_reason: FinishReason,
    /// Token-level log probabilities (if requested).
    pub logprobs: Option<Vec<TokenLogprob>>,
}

/// Why generation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinishReason {
    /// max_tokens reached.
    Length,
    /// Stop sequence encountered.
    Stop,
    /// End-of-sequence token generated.
    EndOfText,
}

/// Log probability for a single generated token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLogprob {
    /// Token text.
    pub token: String,
    /// Token ID.
    pub token_id: u32,
    /// Log probability.
    pub logprob: f64,
    /// Top-5 alternative tokens.
    pub top_alternatives: Vec<(String, f64)>,
}

/// Model version metadata included in every response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersion {
    /// Architecture name.
    pub architecture: String,
    /// Parameter count (human readable).
    pub parameters: String,
    /// Training step of the checkpoint used.
    pub training_step: u64,
    /// Tokens processed during training.
    pub tokens_trained: u64,
    /// Is this a partially-trained model?
    pub is_partial: bool,
    /// Training progress (0.0 - 1.0).
    pub training_progress: f64,
}

// ────────────────────────────────────────────────────────────────────────
// Model Info API
// ────────────────────────────────────────────────────────────────────────

/// Full model information response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfoResponse {
    /// Model architecture config.
    pub config: TransformerConfig,
    /// Current training state.
    pub training_step: u64,
    /// Total tokens trained.
    pub tokens_trained: u64,
    /// Training progress.
    pub training_progress: f64,
    /// Current training loss.
    pub training_loss: f64,
    /// Latest benchmark scores.
    pub benchmark_scores: BenchmarkScores,
    /// Number of nodes currently training.
    pub active_training_nodes: u32,
    /// Global training throughput (tokens/sec).
    pub global_throughput: f64,
    /// Estimated time to completion.
    pub eta_hours: f64,
    /// Whether the model is currently being trained.
    pub is_training: bool,
    /// Whether inference is available.
    pub inference_available: bool,
}

/// Checkpoint listing response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointListResponse {
    /// All available checkpoints.
    pub checkpoints: Vec<CheckpointInfo>,
    /// Latest checkpoint step.
    pub latest_step: u64,
}

/// Summary info about a checkpoint (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// Training step.
    pub step: u64,
    /// Tokens processed.
    pub tokens_processed: u64,
    /// Training loss at this checkpoint.
    pub training_loss: f64,
    /// Validation perplexity (if evaluated).
    pub perplexity: Option<f64>,
    /// Average benchmark accuracy (if evaluated).
    pub avg_accuracy: Option<f64>,
    /// Number of weight shards.
    pub num_shards: u32,
    /// Total size of all weight shards.
    pub total_size_bytes: u64,
    /// Download URLs for weight shards.
    pub shard_urls: Vec<String>,
    /// When this checkpoint was saved.
    pub saved_at: u64,
}

/// Weight download request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightDownloadRequest {
    /// Checkpoint step (None = latest).
    pub checkpoint_step: Option<u64>,
    /// Specific shard index to download (None = all).
    pub shard_index: Option<u32>,
    /// Format preference.
    pub format: WeightFormat,
}

/// Format for downloadable weights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WeightFormat {
    /// SafeTensors (HuggingFace standard, recommended).
    SafeTensors,
    /// PyTorch state dict (.bin).
    PyTorch,
    /// GGUF (for llama.cpp / local inference).
    GGUF,
}

// ────────────────────────────────────────────────────────────────────────
// Serving Configuration
// ────────────────────────────────────────────────────────────────────────

/// Configuration for the inference serving layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServingConfig {
    /// Maximum concurrent inference requests.
    pub max_concurrent_requests: u32,
    /// Maximum tokens per request.
    pub max_tokens_per_request: u32,
    /// Maximum prompt length in tokens.
    pub max_prompt_tokens: u32,
    /// Rate limit: requests per minute per IP.
    pub rate_limit_rpm: u32,
    /// Whether inference is enabled during training.
    pub serve_during_training: bool,
    /// Inference mode.
    pub inference_mode: InferenceMode,
    /// Which checkpoints are available for inference.
    pub available_checkpoints: Vec<u64>,
}

/// How inference is executed across the node cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InferenceMode {
    /// Single node gathers all weight shards and runs inference.
    /// Works for models that fit in one node's RAM (e.g., 8B in 64GB).
    Gathered,
    /// Inference is pipelined across multiple nodes.
    /// Required for large models (70B+).
    Pipeline,
    /// Inference is disabled (training only).
    Disabled,
}

impl Default for ServingConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 16,
            max_tokens_per_request: 4096,
            max_prompt_tokens: 8192,
            rate_limit_rpm: 60,
            serve_during_training: true,
            inference_mode: InferenceMode::Gathered,
            available_checkpoints: vec![],
        }
    }
}

impl ServingConfig {
    /// Config for a model that fits in a single node.
    pub fn single_node() -> Self {
        Self {
            inference_mode: InferenceMode::Gathered,
            ..Default::default()
        }
    }

    /// Config for a large model requiring pipeline inference.
    pub fn pipeline() -> Self {
        Self {
            inference_mode: InferenceMode::Pipeline,
            max_concurrent_requests: 4, // Fewer concurrent for pipeline
            ..Default::default()
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Serving State
// ────────────────────────────────────────────────────────────────────────

/// Runtime state of the serving layer.
pub struct ServingState {
    /// Configuration.
    pub config: ServingConfig,
    /// Active inference requests.
    pub active_requests: u32,
    /// Total requests served.
    pub total_requests: u64,
    /// Total tokens generated.
    pub total_tokens_generated: u64,
    /// Average latency (ms).
    pub avg_latency_ms: f64,
}

impl ServingState {
    pub fn new(config: ServingConfig) -> Self {
        Self {
            config,
            active_requests: 0,
            total_requests: 0,
            total_tokens_generated: 0,
            avg_latency_ms: 0.0,
        }
    }

    /// Check if a new request can be accepted.
    pub fn can_accept_request(&self) -> bool {
        self.active_requests < self.config.max_concurrent_requests
            && self.config.inference_mode != InferenceMode::Disabled
    }

    /// Record a completed request.
    pub fn record_request(&mut self, tokens_generated: u32, latency_ms: u64) {
        self.total_requests += 1;
        self.total_tokens_generated += tokens_generated as u64;
        // Exponential moving average for latency
        let alpha = 0.1;
        self.avg_latency_ms = alpha * latency_ms as f64 + (1.0 - alpha) * self.avg_latency_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_inference_request() {
        let req = InferenceRequest::simple("What is the capital of France?", 100);
        assert_eq!(req.max_tokens, 100);
        assert!((req.sampling.temperature - 0.7).abs() < f64::EPSILON);
        assert_eq!(req.n, 1);
    }

    #[test]
    fn test_serving_config_defaults() {
        let config = ServingConfig::default();
        assert_eq!(config.max_concurrent_requests, 16);
        assert_eq!(config.rate_limit_rpm, 60);
        assert!(config.serve_during_training);
    }

    #[test]
    fn test_serving_state_capacity() {
        let mut state = ServingState::new(ServingConfig::default());
        assert!(state.can_accept_request());

        // Simulate filling up
        state.active_requests = 16;
        assert!(!state.can_accept_request());
    }

    #[test]
    fn test_serving_state_metrics() {
        let mut state = ServingState::new(ServingConfig::default());
        state.record_request(100, 500);
        state.record_request(50, 300);
        assert_eq!(state.total_requests, 2);
        assert_eq!(state.total_tokens_generated, 150);
        assert!(state.avg_latency_ms > 0.0);
    }

    #[test]
    fn test_disabled_serving() {
        let config = ServingConfig {
            inference_mode: InferenceMode::Disabled,
            ..Default::default()
        };
        let state = ServingState::new(config);
        assert!(!state.can_accept_request());
    }

    #[test]
    fn test_inference_request_serialization() {
        let req = InferenceRequest::simple("Hello", 50);
        let json = serde_json::to_string(&req).unwrap();
        let decoded: InferenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.prompt, "Hello");
        assert_eq!(decoded.max_tokens, 50);
    }
}
