//! Dataset registry for distributed training.
//!
//! All training data is stored externally (HuggingFace Hub, etc.) — nothing
//! is bundled in this repository. This module provides:
//!
//! - A catalog of known training datasets with download instructions
//! - Shard manifests for splitting data across consumer nodes
//! - Assignment logic for 64GB RAM / 2TB disk node constraints
//!
//! ## Supported Datasets
//!
//! | Dataset | Tokens | Size | Source |
//! |---------|--------|------|--------|
//! | FineWeb | 15T | ~45TB | HuggingFace |
//! | FineWeb-Edu | 1.3T | ~4TB | HuggingFace |
//! | The Stack v2 | 900B | ~3.3TB | HuggingFace |
//! | RedPajama v2 | 30T | ~100TB | HuggingFace |
//! | OpenWebMath | 14.7B | ~55GB | HuggingFace |

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ────────────────────────────────────────────────────────────────────────
// Dataset Manifest
// ────────────────────────────────────────────────────────────────────────

/// Identifier for a registered dataset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DatasetId(pub String);

impl std::fmt::Display for DatasetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Format of the dataset files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFormat {
    /// Apache Parquet (used by HuggingFace datasets)
    Parquet,
    /// JSON Lines (one JSON object per line)
    JsonLines,
    /// Raw text files
    PlainText,
    /// Pre-tokenized binary (token IDs as u32/u16)
    PreTokenized,
}

/// License under which a dataset is distributed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLicense {
    /// SPDX-style identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// URL to the full license text.
    pub url: String,
}

/// Complete manifest describing a training dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManifest {
    /// Unique dataset identifier.
    pub id: DatasetId,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Base URL for downloading (HuggingFace repo URL).
    pub base_url: String,
    /// HuggingFace repo ID (e.g., "HuggingFaceFW/fineweb").
    pub hf_repo_id: String,
    /// Total size in bytes (approximate).
    pub total_size_bytes: u64,
    /// Total number of tokens.
    pub total_tokens: u64,
    /// File format.
    pub format: DataFormat,
    /// Number of shard files.
    pub num_shards: u32,
    /// URL pattern for individual shard files.
    /// Use `{shard_idx}` as placeholder (e.g., "data/train-{shard_idx:05d}-of-10000.parquet").
    pub shard_url_pattern: String,
    /// Text field name within each record (e.g., "text").
    pub text_field: String,
    /// License.
    pub license: DataLicense,
    /// Which training phases this dataset is used for.
    pub phase: TrainingPhase,
    /// Content categories.
    pub categories: Vec<String>,
}

/// Training phase that a dataset is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingPhase {
    /// Pre-training on large web corpora.
    PreTraining,
    /// Fine-tuning on curated instruction data.
    FineTuning,
    /// Code-specific pre-training.
    CodePreTraining,
    /// Math-specific pre-training.
    MathPreTraining,
    /// Evaluation / benchmarks.
    Evaluation,
}

// ────────────────────────────────────────────────────────────────────────
// Data Shards
// ────────────────────────────────────────────────────────────────────────

/// A single shard of a dataset (one file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataShard {
    /// Dataset this shard belongs to.
    pub dataset_id: DatasetId,
    /// Shard index within the dataset.
    pub shard_index: u32,
    /// Download URL for this specific shard.
    pub url: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Approximate token count in this shard.
    pub approx_tokens: u64,
    /// SHA-256 hash for integrity verification (hex string).
    pub sha256: Option<String>,
    /// Whether this shard has been processed in the current training run.
    pub processed: bool,
    /// Worker that processed or is processing this shard.
    pub assigned_to: Option<Address>,
}

impl DataShard {
    /// Size in human-readable format.
    pub fn size_human(&self) -> String {
        if self.size_bytes >= 1_000_000_000 {
            format!("{:.1} GB", self.size_bytes as f64 / 1e9)
        } else if self.size_bytes >= 1_000_000 {
            format!("{:.1} MB", self.size_bytes as f64 / 1e6)
        } else {
            format!("{:.1} KB", self.size_bytes as f64 / 1e3)
        }
    }
}

/// Assignment of data shards to a worker node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataShardAssignment {
    /// Worker receiving this assignment.
    pub worker: Address,
    /// Ordered list of shard indices to process.
    pub shard_indices: Vec<u32>,
    /// Dataset these shards belong to.
    pub dataset_id: DatasetId,
    /// Total tokens assigned.
    pub total_tokens: u64,
    /// Total bytes to download.
    pub total_bytes: u64,
}

// ────────────────────────────────────────────────────────────────────────
// Tokenizer Configuration
// ────────────────────────────────────────────────────────────────────────

/// Tokenizer configuration (BPE, matching Llama-3 tokenizer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizerConfig {
    /// Tokenizer type.
    pub tokenizer_type: String,
    /// Vocabulary size (must match model's vocab_size).
    pub vocab_size: u32,
    /// HuggingFace model ID to load the tokenizer from.
    pub hf_tokenizer_id: String,
    /// Special tokens.
    pub bos_token: String,
    pub eos_token: String,
    pub pad_token: String,
}

impl TokenizerConfig {
    /// Llama-3 tokenizer config.
    pub fn llama3() -> Self {
        Self {
            tokenizer_type: "BPE".to_string(),
            vocab_size: 128256,
            hf_tokenizer_id: "meta-llama/Meta-Llama-3-8B".to_string(),
            bos_token: "<|begin_of_text|>".to_string(),
            eos_token: "<|end_of_text|>".to_string(),
            pad_token: "<|finetune_right_pad_id|>".to_string(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Dataset Registry
// ────────────────────────────────────────────────────────────────────────

/// Central registry of available training datasets.
///
/// Node operators use this to discover and download the data they need.
/// Data is NEVER stored in this repository — only references.
pub struct DatasetRegistry {
    /// All registered dataset manifests.
    pub manifests: HashMap<DatasetId, DatasetManifest>,
    /// Current shard assignments per dataset.
    pub assignments: HashMap<DatasetId, Vec<DataShardAssignment>>,
    /// Global progress: how many tokens have been processed per dataset.
    pub tokens_processed: HashMap<DatasetId, u64>,
    /// Current epoch (how many times we've cycled through the data).
    pub current_epoch: u32,
}

impl DatasetRegistry {
    /// Create registry with all known datasets pre-registered.
    pub fn new() -> Self {
        let mut registry = Self {
            manifests: HashMap::new(),
            assignments: HashMap::new(),
            tokens_processed: HashMap::new(),
            current_epoch: 0,
        };
        registry.register_builtin_datasets();
        registry
    }

    /// Register all built-in dataset references.
    fn register_builtin_datasets(&mut self) {
        // ── FineWeb (primary pre-training corpus) ──
        self.manifests.insert(
            DatasetId("fineweb".to_string()),
            DatasetManifest {
                id: DatasetId("fineweb".to_string()),
                name: "FineWeb".to_string(),
                description: "15T tokens of cleaned, deduplicated English web text from 96 CommonCrawl snapshots (2013-2024).".to_string(),
                base_url: "https://huggingface.co/datasets/HuggingFaceFW/fineweb".to_string(),
                hf_repo_id: "HuggingFaceFW/fineweb".to_string(),
                total_size_bytes: 45_000_000_000_000, // ~45TB
                total_tokens: 15_000_000_000_000,     // 15T tokens
                format: DataFormat::Parquet,
                num_shards: 100_000,
                shard_url_pattern: "data/CC-MAIN-*/train-{shard_idx:05d}.parquet".to_string(),
                text_field: "text".to_string(),
                license: DataLicense {
                    id: "ODC-By-1.0".to_string(),
                    name: "Open Data Commons Attribution License".to_string(),
                    url: "https://opendatacommons.org/licenses/by/1-0/".to_string(),
                },
                phase: TrainingPhase::PreTraining,
                categories: vec!["web".to_string(), "english".to_string()],
            },
        );

        // ── FineWeb-Edu (high-quality educational subset) ──
        self.manifests.insert(
            DatasetId("fineweb-edu".to_string()),
            DatasetManifest {
                id: DatasetId("fineweb-edu".to_string()),
                name: "FineWeb-Edu".to_string(),
                description: "1.3T tokens of educational web content, filtered from FineWeb for high-quality factual content.".to_string(),
                base_url: "https://huggingface.co/datasets/HuggingFaceFW/fineweb-edu".to_string(),
                hf_repo_id: "HuggingFaceFW/fineweb-edu".to_string(),
                total_size_bytes: 4_000_000_000_000, // ~4TB
                total_tokens: 1_300_000_000_000,     // 1.3T tokens
                format: DataFormat::Parquet,
                num_shards: 10_000,
                shard_url_pattern: "data/train-{shard_idx:05d}-of-10000.parquet".to_string(),
                text_field: "text".to_string(),
                license: DataLicense {
                    id: "ODC-By-1.0".to_string(),
                    name: "Open Data Commons Attribution License".to_string(),
                    url: "https://opendatacommons.org/licenses/by/1-0/".to_string(),
                },
                phase: TrainingPhase::PreTraining,
                categories: vec!["web".to_string(), "educational".to_string()],
            },
        );

        // ── The Stack v2 (code pre-training) ──
        self.manifests.insert(
            DatasetId("the-stack-v2".to_string()),
            DatasetManifest {
                id: DatasetId("the-stack-v2".to_string()),
                name: "The Stack v2".to_string(),
                description: "900B tokens of source code in 600+ programming languages.".to_string(),
                base_url: "https://huggingface.co/datasets/bigcode/the-stack-v2".to_string(),
                hf_repo_id: "bigcode/the-stack-v2".to_string(),
                total_size_bytes: 3_300_000_000_000, // ~3.3TB
                total_tokens: 900_000_000_000,       // 900B tokens
                format: DataFormat::Parquet,
                num_shards: 8_000,
                shard_url_pattern: "data/train-{shard_idx:05d}-of-08000.parquet".to_string(),
                text_field: "content".to_string(),
                license: DataLicense {
                    id: "Mixed-OSS".to_string(),
                    name: "Mixed Open Source Licenses (per-file)".to_string(),
                    url: "https://huggingface.co/datasets/bigcode/the-stack-v2#licensing".to_string(),
                },
                phase: TrainingPhase::CodePreTraining,
                categories: vec!["code".to_string(), "programming".to_string()],
            },
        );

        // ── RedPajama v2 (massive diverse corpus) ──
        self.manifests.insert(
            DatasetId("redpajama-v2".to_string()),
            DatasetManifest {
                id: DatasetId("redpajama-v2".to_string()),
                name: "RedPajama v2".to_string(),
                description: "30T raw tokens from web, books, code, wikipedia, arxiv. Pre-filtered to ~5T high-quality tokens.".to_string(),
                base_url: "https://huggingface.co/datasets/togethercomputer/RedPajama-Data-V2".to_string(),
                hf_repo_id: "togethercomputer/RedPajama-Data-V2".to_string(),
                total_size_bytes: 100_000_000_000_000, // ~100TB raw
                total_tokens: 30_000_000_000_000,      // 30T raw tokens
                format: DataFormat::JsonLines,
                num_shards: 200_000,
                shard_url_pattern: "data/{shard_idx:06d}.jsonl.gz".to_string(),
                text_field: "raw_content".to_string(),
                license: DataLicense {
                    id: "Apache-2.0".to_string(),
                    name: "Apache License 2.0".to_string(),
                    url: "https://www.apache.org/licenses/LICENSE-2.0".to_string(),
                },
                phase: TrainingPhase::PreTraining,
                categories: vec!["web".to_string(), "books".to_string(), "code".to_string(), "academic".to_string()],
            },
        );

        // ── OpenWebMath (math-specific pre-training) ──
        self.manifests.insert(
            DatasetId("open-web-math".to_string()),
            DatasetManifest {
                id: DatasetId("open-web-math".to_string()),
                name: "OpenWebMath".to_string(),
                description: "14.7B tokens of mathematical web content (LaTeX, proofs, problem solutions).".to_string(),
                base_url: "https://huggingface.co/datasets/open-web-math/open-web-math".to_string(),
                hf_repo_id: "open-web-math/open-web-math".to_string(),
                total_size_bytes: 55_000_000_000, // ~55GB
                total_tokens: 14_700_000_000,     // 14.7B tokens
                format: DataFormat::Parquet,
                num_shards: 500,
                shard_url_pattern: "data/train-{shard_idx:05d}-of-00500.parquet".to_string(),
                text_field: "text".to_string(),
                license: DataLicense {
                    id: "ODC-By-1.0".to_string(),
                    name: "Open Data Commons Attribution License".to_string(),
                    url: "https://opendatacommons.org/licenses/by/1-0/".to_string(),
                },
                phase: TrainingPhase::MathPreTraining,
                categories: vec!["math".to_string(), "academic".to_string()],
            },
        );
    }

    /// Get all datasets for a given training phase.
    pub fn datasets_for_phase(&self, phase: TrainingPhase) -> Vec<&DatasetManifest> {
        self.manifests.values().filter(|m| m.phase == phase).collect()
    }

    /// Generate shard references for a dataset.
    pub fn generate_shards(&self, dataset_id: &DatasetId) -> Vec<DataShard> {
        let manifest = match self.manifests.get(dataset_id) {
            Some(m) => m,
            None => return vec![],
        };

        let tokens_per_shard = manifest.total_tokens / manifest.num_shards as u64;
        let bytes_per_shard = manifest.total_size_bytes / manifest.num_shards as u64;

        (0..manifest.num_shards).map(|i| {
            let url = manifest.shard_url_pattern
                .replace("{shard_idx:05d}", &format!("{:05}", i))
                .replace("{shard_idx:06d}", &format!("{:06}", i));

            DataShard {
                dataset_id: dataset_id.clone(),
                shard_index: i,
                url: format!("{}/resolve/main/{}", manifest.base_url, url),
                size_bytes: bytes_per_shard,
                approx_tokens: tokens_per_shard,
                sha256: None, // Computed on download
                processed: false,
                assigned_to: None,
            }
        }).collect()
    }

    /// Assign data shards to workers, respecting disk constraints.
    ///
    /// `disk_budget_bytes`: Max disk space per worker (e.g., 50GB for a 2TB node).
    /// Workers only download their assigned shards, process them, and discard.
    pub fn assign_shards(
        &self,
        dataset_id: &DatasetId,
        workers: &[Address],
        disk_budget_bytes: u64,
    ) -> Vec<DataShardAssignment> {
        let shards = self.generate_shards(dataset_id);
        if shards.is_empty() || workers.is_empty() {
            return vec![];
        }

        let bytes_per_shard = shards.first().map(|s| s.size_bytes).unwrap_or(0);
        let max_shards_per_worker = if bytes_per_shard > 0 {
            (disk_budget_bytes / bytes_per_shard) as usize
        } else {
            shards.len()
        };

        let shards_per_worker = (shards.len() / workers.len()).min(max_shards_per_worker);

        workers.iter().enumerate().map(|(i, worker)| {
            let start = i * shards_per_worker;
            let end = (start + shards_per_worker).min(shards.len());
            let assigned: Vec<u32> = (start..end).map(|j| shards[j].shard_index).collect();
            let total_tokens: u64 = assigned.len() as u64 * shards[0].approx_tokens;
            let total_bytes: u64 = assigned.len() as u64 * shards[0].size_bytes;

            DataShardAssignment {
                worker: *worker,
                shard_indices: assigned,
                dataset_id: dataset_id.clone(),
                total_tokens,
                total_bytes,
            }
        }).collect()
    }

    /// Generate download instructions for node operators.
    pub fn download_instructions(&self, dataset_id: &DatasetId) -> String {
        let manifest = match self.manifests.get(dataset_id) {
            Some(m) => m,
            None => return "Dataset not found.".to_string(),
        };

        format!(
            r#"# Download Instructions: {}

## Option 1: HuggingFace CLI (recommended)
```bash
pip install huggingface-cli
huggingface-cli download {} --repo-type dataset --local-dir ./data/{}
```

## Option 2: Python datasets library (streaming)
```python
from datasets import load_dataset
ds = load_dataset("{}", streaming=True)
for example in ds["train"]:
    text = example["{}"]
    # Process text...
```

## Option 3: Download specific shards only
Your node will be assigned specific shards. Download only those:
```bash
# Example: download shard 42
wget {}/resolve/main/{}
```

## Dataset Info
- **Size**: {:.1} TB ({} shards)
- **Tokens**: {:.1}T
- **Format**: {:?}
- **License**: {} ({})
- **Text field**: "{}"
"#,
            manifest.name,
            manifest.hf_repo_id,
            manifest.id.0,
            manifest.hf_repo_id,
            manifest.text_field,
            manifest.base_url,
            manifest.shard_url_pattern.replace("{shard_idx:05d}", "00042").replace("{shard_idx:06d}", "000042"),
            manifest.total_size_bytes as f64 / 1e12,
            manifest.num_shards,
            manifest.total_tokens as f64 / 1e12,
            manifest.format,
            manifest.license.name,
            manifest.license.url,
            manifest.text_field,
        )
    }

    /// Get the combined training mix for pre-training.
    /// Returns datasets weighted by their contribution to the training mix.
    pub fn pretraining_mix(&self) -> Vec<(DatasetId, f64)> {
        // Standard mix ratios (inspired by Llama-3 training mix):
        // 75% general web, 10% code, 10% educational, 5% math
        vec![
            (DatasetId("fineweb".to_string()), 0.75),
            (DatasetId("the-stack-v2".to_string()), 0.10),
            (DatasetId("fineweb-edu".to_string()), 0.10),
            (DatasetId("open-web-math".to_string()), 0.05),
        ]
    }

    /// Total training tokens across the default pre-training mix.
    pub fn total_pretraining_tokens(&self) -> u64 {
        self.pretraining_mix().iter()
            .map(|(id, weight)| {
                let tokens = self.manifests.get(id)
                    .map(|m| m.total_tokens)
                    .unwrap_or(0);
                (tokens as f64 * weight) as u64
            })
            .sum()
    }
}

// ────────────────────────────────────────────────────────────────────────
// Node Storage Requirements
// ────────────────────────────────────────────────────────────────────────

/// Storage requirements for a consumer node (64GB RAM, 2TB disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStorageRequirements {
    /// Total disk capacity (bytes).
    pub disk_capacity_bytes: u64,
    /// Disk reserved for OS, applications, and model weights.
    pub reserved_bytes: u64,
    /// Disk available for training data shards.
    pub available_for_data_bytes: u64,
    /// How many data shards can be stored at once.
    pub max_concurrent_shards: u32,
    /// Data is streamed: download shard → tokenize → process → delete → next shard.
    pub streaming_mode: bool,
}

impl NodeStorageRequirements {
    /// Calculate for a consumer node with the given specs.
    pub fn for_consumer_node(disk_tb: f64) -> Self {
        let disk_bytes = (disk_tb * 1e12) as u64;
        // Reserve 200GB for OS + model weights + system
        let reserved = 200_000_000_000u64;
        let available = disk_bytes.saturating_sub(reserved);

        Self {
            disk_capacity_bytes: disk_bytes,
            reserved_bytes: reserved,
            available_for_data_bytes: available,
            // Each FineWeb shard is ~450MB, keep at most 100 shards buffered
            max_concurrent_shards: (available / 450_000_000).min(100) as u32,
            streaming_mode: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_all_datasets() {
        let registry = DatasetRegistry::new();
        assert!(registry.manifests.contains_key(&DatasetId("fineweb".to_string())));
        assert!(registry.manifests.contains_key(&DatasetId("fineweb-edu".to_string())));
        assert!(registry.manifests.contains_key(&DatasetId("the-stack-v2".to_string())));
        assert!(registry.manifests.contains_key(&DatasetId("redpajama-v2".to_string())));
        assert!(registry.manifests.contains_key(&DatasetId("open-web-math".to_string())));
        assert_eq!(registry.manifests.len(), 5);
    }

    #[test]
    fn test_generate_shards() {
        let registry = DatasetRegistry::new();
        let shards = registry.generate_shards(&DatasetId("open-web-math".to_string()));
        assert_eq!(shards.len(), 500);
        assert!(shards[0].url.contains("huggingface.co"));
        assert!(shards[0].approx_tokens > 0);
    }

    #[test]
    fn test_shard_assignment() {
        let registry = DatasetRegistry::new();
        let workers = vec![
            Address::from([0x01; 20]),
            Address::from([0x02; 20]),
            Address::from([0x03; 20]),
        ];
        // 50GB disk budget per worker
        let assignments = registry.assign_shards(
            &DatasetId("open-web-math".to_string()),
            &workers,
            50_000_000_000,
        );
        assert_eq!(assignments.len(), 3);
        // Each worker should get ~166 shards (500/3)
        assert!(assignments[0].shard_indices.len() > 100);
        // No overlap between workers
        let all_indices: Vec<u32> = assignments.iter()
            .flat_map(|a| a.shard_indices.iter().copied())
            .collect();
        let unique: std::collections::HashSet<u32> = all_indices.iter().copied().collect();
        assert_eq!(all_indices.len(), unique.len());
    }

    #[test]
    fn test_pretraining_mix() {
        let registry = DatasetRegistry::new();
        let mix = registry.pretraining_mix();
        let total_weight: f64 = mix.iter().map(|(_, w)| w).sum();
        assert!((total_weight - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_consumer_node_storage() {
        let req = NodeStorageRequirements::for_consumer_node(2.0);
        assert!(req.available_for_data_bytes > 1_500_000_000_000); // >1.5TB available
        assert!(req.max_concurrent_shards > 50);
        assert!(req.streaming_mode);
    }

    #[test]
    fn test_download_instructions() {
        let registry = DatasetRegistry::new();
        let instructions = registry.download_instructions(&DatasetId("fineweb".to_string()));
        assert!(instructions.contains("huggingface-cli"));
        assert!(instructions.contains("HuggingFaceFW/fineweb"));
        assert!(instructions.contains("Open Data Commons") || instructions.contains("ODC"));
    }

    #[test]
    fn test_datasets_for_phase() {
        let registry = DatasetRegistry::new();
        let pretrain = registry.datasets_for_phase(TrainingPhase::PreTraining);
        assert!(pretrain.len() >= 2); // FineWeb + RedPajama
        let code = registry.datasets_for_phase(TrainingPhase::CodePreTraining);
        assert_eq!(code.len(), 1); // The Stack
    }
}
