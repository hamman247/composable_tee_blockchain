//! Benchmark evaluation framework for measuring model quality.
//!
//! Implements standard LLM evaluation benchmarks with frontier-level
//! target scores. Evaluation data is downloaded from public sources
//! (HuggingFace datasets / GitHub repos).
//!
//! ## Benchmarks
//!
//! | Benchmark | Metric | Frontier Target (2025) |
//! |-----------|--------|----------------------|
//! | Perplexity | Lower = better | < 3.0 |
//! | MMLU | 5-shot accuracy | > 88% |
//! | HumanEval | pass@1 | > 85% |
//! | GSM8K | Accuracy | > 92% |
//! | ARC-Challenge | Accuracy | > 92% |
//! | TruthfulQA | MC accuracy | > 75% |
//! | MATH | Accuracy | > 68% |
//! | WinoGrande | Accuracy | > 87% |

use serde::{Deserialize, Serialize};
use crate::model::BenchmarkScores;

// ────────────────────────────────────────────────────────────────────────
// Benchmark Definitions
// ────────────────────────────────────────────────────────────────────────

/// A single evaluation benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Benchmark {
    /// Unique identifier.
    pub id: BenchmarkId,
    /// Human-readable name.
    pub name: String,
    /// Description of what this benchmark measures.
    pub description: String,
    /// Where to get the evaluation data.
    pub data_source: BenchmarkDataSource,
    /// Metric type.
    pub metric: MetricType,
    /// Number of few-shot examples (0 for zero-shot).
    pub num_shots: u32,
    /// Number of evaluation examples.
    pub num_examples: u32,
    /// Frontier model target score (GPT-4o / Claude 3.5 class, 2025).
    pub frontier_target: f64,
    /// "Good enough" threshold for a competitive model.
    pub competitive_threshold: f64,
}

/// Benchmark identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BenchmarkId {
    Perplexity,
    MMLU,
    HumanEval,
    GSM8K,
    ArcChallenge,
    TruthfulQA,
    MATH,
    WinoGrande,
}

impl std::fmt::Display for BenchmarkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Perplexity => write!(f, "Perplexity"),
            Self::MMLU => write!(f, "MMLU"),
            Self::HumanEval => write!(f, "HumanEval"),
            Self::GSM8K => write!(f, "GSM8K"),
            Self::ArcChallenge => write!(f, "ARC-Challenge"),
            Self::TruthfulQA => write!(f, "TruthfulQA"),
            Self::MATH => write!(f, "MATH"),
            Self::WinoGrande => write!(f, "WinoGrande"),
        }
    }
}

/// Source for benchmark evaluation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkDataSource {
    /// HuggingFace dataset ID or GitHub URL.
    pub source_url: String,
    /// HuggingFace repo ID (if applicable).
    pub hf_repo_id: Option<String>,
    /// Split to use for evaluation.
    pub split: String,
    /// Size in bytes (approximate).
    pub size_bytes: u64,
}

/// Type of metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    /// Lower is better (e.g., perplexity).
    LowerIsBetter,
    /// Higher is better, measured as percentage (0-100).
    Accuracy,
    /// Higher is better, measured as pass@k.
    PassAtK,
}

// ────────────────────────────────────────────────────────────────────────
// Benchmark Suite
// ────────────────────────────────────────────────────────────────────────

/// Complete benchmark evaluation suite.
pub struct BenchmarkSuite {
    /// All registered benchmarks.
    pub benchmarks: Vec<Benchmark>,
}

impl BenchmarkSuite {
    /// Create the standard evaluation suite.
    pub fn standard() -> Self {
        Self {
            benchmarks: vec![
                Benchmark {
                    id: BenchmarkId::Perplexity,
                    name: "Perplexity".to_string(),
                    description: "Language modeling perplexity on held-out web text. Measures raw language understanding.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/HuggingFaceFW/fineweb".to_string(),
                        hf_repo_id: Some("HuggingFaceFW/fineweb".to_string()),
                        split: "test".to_string(),
                        size_bytes: 100_000_000, // 100MB test split
                    },
                    metric: MetricType::LowerIsBetter,
                    num_shots: 0,
                    num_examples: 10_000,
                    frontier_target: 2.5,
                    competitive_threshold: 5.0,
                },
                Benchmark {
                    id: BenchmarkId::MMLU,
                    name: "MMLU (5-shot)".to_string(),
                    description: "Massive Multitask Language Understanding: 57 subjects from STEM to humanities. Tests broad knowledge.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/cais/mmlu".to_string(),
                        hf_repo_id: Some("cais/mmlu".to_string()),
                        split: "test".to_string(),
                        size_bytes: 50_000_000,
                    },
                    metric: MetricType::Accuracy,
                    num_shots: 5,
                    num_examples: 14_042,
                    frontier_target: 88.0,
                    competitive_threshold: 70.0,
                },
                Benchmark {
                    id: BenchmarkId::HumanEval,
                    name: "HumanEval".to_string(),
                    description: "Python code generation: 164 programming problems with test cases. Tests coding ability.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://github.com/openai/human-eval".to_string(),
                        hf_repo_id: Some("openai/humaneval".to_string()),
                        split: "test".to_string(),
                        size_bytes: 1_000_000,
                    },
                    metric: MetricType::PassAtK,
                    num_shots: 0,
                    num_examples: 164,
                    frontier_target: 85.0,
                    competitive_threshold: 50.0,
                },
                Benchmark {
                    id: BenchmarkId::GSM8K,
                    name: "GSM8K".to_string(),
                    description: "Grade school math: 8.5K multi-step math word problems. Tests mathematical reasoning.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/openai/gsm8k".to_string(),
                        hf_repo_id: Some("openai/gsm8k".to_string()),
                        split: "test".to_string(),
                        size_bytes: 5_000_000,
                    },
                    metric: MetricType::Accuracy,
                    num_shots: 8,
                    num_examples: 1_319,
                    frontier_target: 92.0,
                    competitive_threshold: 60.0,
                },
                Benchmark {
                    id: BenchmarkId::ArcChallenge,
                    name: "ARC-Challenge".to_string(),
                    description: "AI2 Reasoning Challenge: grade-school science questions. Tests scientific reasoning.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/allenai/ai2_arc".to_string(),
                        hf_repo_id: Some("allenai/ai2_arc".to_string()),
                        split: "test".to_string(),
                        size_bytes: 3_000_000,
                    },
                    metric: MetricType::Accuracy,
                    num_shots: 25,
                    num_examples: 1_172,
                    frontier_target: 92.0,
                    competitive_threshold: 70.0,
                },
                Benchmark {
                    id: BenchmarkId::TruthfulQA,
                    name: "TruthfulQA".to_string(),
                    description: "Measures factual accuracy and resistance to common misconceptions. Tests truthfulness.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/truthful_qa".to_string(),
                        hf_repo_id: Some("truthful_qa".to_string()),
                        split: "validation".to_string(),
                        size_bytes: 2_000_000,
                    },
                    metric: MetricType::Accuracy,
                    num_shots: 6,
                    num_examples: 817,
                    frontier_target: 75.0,
                    competitive_threshold: 50.0,
                },
                Benchmark {
                    id: BenchmarkId::MATH,
                    name: "MATH".to_string(),
                    description: "Competition-level mathematics: algebra, geometry, number theory, calculus. Tests advanced reasoning.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/lighteval/MATH".to_string(),
                        hf_repo_id: Some("lighteval/MATH".to_string()),
                        split: "test".to_string(),
                        size_bytes: 10_000_000,
                    },
                    metric: MetricType::Accuracy,
                    num_shots: 4,
                    num_examples: 5_000,
                    frontier_target: 68.0,
                    competitive_threshold: 30.0,
                },
                Benchmark {
                    id: BenchmarkId::WinoGrande,
                    name: "WinoGrande".to_string(),
                    description: "Commonsense reasoning via pronoun resolution. Tests world knowledge.".to_string(),
                    data_source: BenchmarkDataSource {
                        source_url: "https://huggingface.co/datasets/allenai/winogrande".to_string(),
                        hf_repo_id: Some("allenai/winogrande".to_string()),
                        split: "validation".to_string(),
                        size_bytes: 5_000_000,
                    },
                    metric: MetricType::Accuracy,
                    num_shots: 5,
                    num_examples: 1_267,
                    frontier_target: 87.0,
                    competitive_threshold: 70.0,
                },
            ],
        }
    }

    /// Get a benchmark by ID.
    pub fn get(&self, id: &BenchmarkId) -> Option<&Benchmark> {
        self.benchmarks.iter().find(|b| b.id == *id)
    }

    /// Total evaluation data size across all benchmarks.
    pub fn total_eval_data_size(&self) -> u64 {
        self.benchmarks.iter().map(|b| b.data_source.size_bytes).sum()
    }
}

// ────────────────────────────────────────────────────────────────────────
// Evaluation Results
// ────────────────────────────────────────────────────────────────────────

/// Result of running a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Benchmark that was evaluated.
    pub benchmark_id: BenchmarkId,
    /// Score achieved.
    pub score: f64,
    /// Number of examples evaluated.
    pub num_evaluated: u32,
    /// Whether this score meets or exceeds the frontier target.
    pub meets_frontier: bool,
    /// Whether this score meets the competitive threshold.
    pub meets_competitive: bool,
    /// Per-category breakdown (for MMLU: per-subject scores, etc.).
    pub category_scores: Vec<(String, f64)>,
    /// Evaluation timestamp.
    pub evaluated_at: u64,
    /// Training step when this evaluation was run.
    pub at_step: u64,
}

impl BenchmarkResult {
    /// Grade this result against targets.
    pub fn grade(&self) -> &str {
        if self.meets_frontier {
            "★ FRONTIER"
        } else if self.meets_competitive {
            "✓ Competitive"
        } else {
            "✗ Below threshold"
        }
    }
}

/// Complete evaluation report for a model checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    /// Training step when evaluation was run.
    pub at_step: u64,
    /// Total tokens processed at evaluation time.
    pub tokens_processed: u64,
    /// Individual benchmark results.
    pub results: Vec<BenchmarkResult>,
    /// Summary: how many benchmarks meet frontier/competitive thresholds.
    pub frontier_count: u32,
    pub competitive_count: u32,
    pub total_benchmarks: u32,
    /// Overall readiness assessment.
    pub assessment: String,
}

impl EvaluationReport {
    /// Create from a list of results.
    pub fn from_results(at_step: u64, tokens_processed: u64, results: Vec<BenchmarkResult>) -> Self {
        let frontier_count = results.iter().filter(|r| r.meets_frontier).count() as u32;
        let competitive_count = results.iter().filter(|r| r.meets_competitive).count() as u32;
        let total = results.len() as u32;

        let assessment = if frontier_count == total {
            "🏆 FRONTIER-LEVEL: All benchmarks meet frontier targets".to_string()
        } else if competitive_count == total {
            format!("✅ COMPETITIVE: All benchmarks competitive, {}/{} at frontier", frontier_count, total)
        } else if competitive_count > total / 2 {
            format!("🔶 PROGRESSING: {}/{} competitive, {}/{} frontier", competitive_count, total, frontier_count, total)
        } else {
            format!("🔴 EARLY STAGE: {}/{} competitive", competitive_count, total)
        };

        Self {
            at_step, tokens_processed, results,
            frontier_count, competitive_count, total_benchmarks: total,
            assessment,
        }
    }

    /// Convert to BenchmarkScores for storage in ModelCheckpoint.
    pub fn to_benchmark_scores(&self) -> BenchmarkScores {
        let mut scores = BenchmarkScores::default();
        for result in &self.results {
            match result.benchmark_id {
                BenchmarkId::Perplexity => scores.perplexity = Some(result.score),
                BenchmarkId::MMLU => scores.mmlu = Some(result.score),
                BenchmarkId::HumanEval => scores.humaneval = Some(result.score),
                BenchmarkId::GSM8K => scores.gsm8k = Some(result.score),
                BenchmarkId::ArcChallenge => scores.arc_challenge = Some(result.score),
                BenchmarkId::TruthfulQA => scores.truthfulqa = Some(result.score),
                BenchmarkId::MATH => scores.math = Some(result.score),
                BenchmarkId::WinoGrande => scores.winogrande = Some(result.score),
            }
        }
        scores
    }

    /// Print a formatted report.
    pub fn format_report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("╔═══ Evaluation Report (Step {}) ═══╗\n", self.at_step));
        out.push_str(&format!("║ Tokens: {:.2}T\n", self.tokens_processed as f64 / 1e12));
        out.push_str("║\n");
        out.push_str("║ Benchmark        Score   Target  Grade\n");
        out.push_str("║ ─────────────── ─────── ─────── ──────────────\n");

        for result in &self.results {
            let score_str = if result.benchmark_id == BenchmarkId::Perplexity {
                format!("{:.2}", result.score)
            } else {
                format!("{:.1}%", result.score)
            };
            let target_str = if result.benchmark_id == BenchmarkId::Perplexity {
                format!("<{:.1}", self.get_frontier_target(&result.benchmark_id))
            } else {
                format!(">{:.0}%", self.get_frontier_target(&result.benchmark_id))
            };
            out.push_str(&format!("║ {:15} {:>7} {:>7} {}\n",
                result.benchmark_id, score_str, target_str, result.grade()));
        }

        out.push_str("║\n");
        out.push_str(&format!("║ {}\n", self.assessment));
        out.push_str("╚═══════════════════════════════════╝\n");
        out
    }

    fn get_frontier_target(&self, id: &BenchmarkId) -> f64 {
        let suite = BenchmarkSuite::standard();
        suite.get(id).map(|b| b.frontier_target).unwrap_or(0.0)
    }
}

// ────────────────────────────────────────────────────────────────────────
// Evaluation Schedule
// ────────────────────────────────────────────────────────────────────────

/// Controls when evaluations are triggered during training.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSchedule {
    /// Run full benchmark suite every N steps.
    pub full_eval_interval: u64,
    /// Run perplexity-only check every N steps.
    pub perplexity_interval: u64,
    /// Run benchmarks at these specific steps (e.g., early milestones).
    pub explicit_steps: Vec<u64>,
}

impl Default for EvaluationSchedule {
    fn default() -> Self {
        Self {
            full_eval_interval: 1000,
            perplexity_interval: 100,
            explicit_steps: vec![100, 500, 1000, 5000, 10000],
        }
    }
}

impl EvaluationSchedule {
    /// Should a full evaluation run at this step?
    pub fn should_full_eval(&self, step: u64) -> bool {
        (step > 0 && step % self.full_eval_interval == 0)
            || self.explicit_steps.contains(&step)
    }

    /// Should a perplexity check run at this step?
    pub fn should_perplexity_check(&self, step: u64) -> bool {
        step > 0 && step % self.perplexity_interval == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_suite_has_all_benchmarks() {
        let suite = BenchmarkSuite::standard();
        assert_eq!(suite.benchmarks.len(), 8);
        assert!(suite.get(&BenchmarkId::MMLU).is_some());
        assert!(suite.get(&BenchmarkId::HumanEval).is_some());
        assert!(suite.get(&BenchmarkId::Perplexity).is_some());
    }

    #[test]
    fn test_frontier_targets_reasonable() {
        let suite = BenchmarkSuite::standard();
        for bench in &suite.benchmarks {
            match bench.metric {
                MetricType::LowerIsBetter => {
                    assert!(bench.frontier_target > 0.0 && bench.frontier_target < 10.0,
                        "{}: frontier target {} out of range", bench.name, bench.frontier_target);
                }
                MetricType::Accuracy | MetricType::PassAtK => {
                    assert!(bench.frontier_target > 50.0 && bench.frontier_target <= 100.0,
                        "{}: frontier target {} out of range", bench.name, bench.frontier_target);
                    assert!(bench.competitive_threshold < bench.frontier_target);
                }
            }
        }
    }

    #[test]
    fn test_evaluation_report_grading() {
        let suite = BenchmarkSuite::standard();
        let results: Vec<BenchmarkResult> = suite.benchmarks.iter().map(|b| {
            let score = match b.metric {
                MetricType::LowerIsBetter => b.frontier_target - 0.5, // Better than frontier
                _ => b.frontier_target + 1.0, // Better than frontier
            };
            BenchmarkResult {
                benchmark_id: b.id.clone(),
                score,
                num_evaluated: b.num_examples,
                meets_frontier: true,
                meets_competitive: true,
                category_scores: vec![],
                evaluated_at: 0,
                at_step: 50000,
            }
        }).collect();

        let report = EvaluationReport::from_results(50000, 1_000_000_000_000, results);
        assert_eq!(report.frontier_count, 8);
        assert!(report.assessment.contains("FRONTIER"));
        let formatted = report.format_report();
        assert!(formatted.contains("MMLU"));
        assert!(formatted.contains("FRONTIER"));
    }

    #[test]
    fn test_evaluation_schedule() {
        let schedule = EvaluationSchedule::default();
        assert!(schedule.should_full_eval(1000));
        assert!(schedule.should_full_eval(2000));
        assert!(schedule.should_full_eval(500)); // explicit step
        assert!(!schedule.should_full_eval(0));
        assert!(schedule.should_perplexity_check(100));
        assert!(schedule.should_perplexity_check(200));
        assert!(!schedule.should_perplexity_check(0));
    }

    #[test]
    fn test_report_to_benchmark_scores() {
        let results = vec![
            BenchmarkResult {
                benchmark_id: BenchmarkId::MMLU, score: 85.0,
                num_evaluated: 14042, meets_frontier: false, meets_competitive: true,
                category_scores: vec![], evaluated_at: 0, at_step: 1000,
            },
            BenchmarkResult {
                benchmark_id: BenchmarkId::Perplexity, score: 3.2,
                num_evaluated: 10000, meets_frontier: false, meets_competitive: true,
                category_scores: vec![], evaluated_at: 0, at_step: 1000,
            },
        ];
        let report = EvaluationReport::from_results(1000, 500_000_000_000, results);
        let scores = report.to_benchmark_scores();
        assert_eq!(scores.mmlu, Some(85.0));
        assert_eq!(scores.perplexity, Some(3.2));
        assert_eq!(scores.humaneval, None); // Not evaluated
    }

    #[test]
    fn test_eval_data_size() {
        let suite = BenchmarkSuite::standard();
        let total = suite.total_eval_data_size();
        // All eval data combined should be <1GB (easily fits on consumer nodes)
        assert!(total < 1_000_000_000, "Eval data should be <1GB, got {}", total);
    }
}
