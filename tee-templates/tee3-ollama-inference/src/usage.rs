//! Usage tracking and mining threshold.
//!
//! The TEE tracks every verified query: who asked, how many tokens
//! were consumed, and latency. After enough usage accumulates,
//! the node operator can mine a block.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default mining threshold: 1000 verified queries.
const DEFAULT_QUERY_THRESHOLD: u64 = 1000;
/// Or 500K tokens processed (whichever comes first).
const DEFAULT_TOKEN_THRESHOLD: u64 = 500_000;

/// A single usage record for one verified query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// User who signed the query.
    pub user: Address,
    /// Model used.
    pub model: String,
    /// Input tokens (prompt).
    pub tokens_in: u32,
    /// Output tokens (response).
    pub tokens_out: u32,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// Timestamp.
    pub timestamp: u64,
}

/// Mining threshold configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningThreshold {
    /// Minimum verified queries before mining is allowed.
    pub min_queries: u64,
    /// Minimum total tokens processed before mining is allowed.
    pub min_tokens: u64,
}

impl Default for MiningThreshold {
    fn default() -> Self {
        Self {
            min_queries: DEFAULT_QUERY_THRESHOLD,
            min_tokens: DEFAULT_TOKEN_THRESHOLD,
        }
    }
}

impl MiningThreshold {
    /// Reduced thresholds for testing.
    pub fn test_mode() -> Self {
        Self {
            min_queries: 5,
            min_tokens: 100,
        }
    }
}

/// Accumulated usage summary for block production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    /// Total verified queries processed.
    pub total_queries: u64,
    /// Total tokens (input + output) processed.
    pub total_tokens: u64,
    /// Unique users served.
    pub unique_users: u32,
    /// Per-user query counts.
    pub per_user: HashMap<Address, UserUsage>,
    /// Model(s) served.
    pub models_served: Vec<String>,
    /// Average latency in ms.
    pub avg_latency_ms: f64,
}

/// Per-user usage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUsage {
    pub queries: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
}

/// Usage tracker — accumulates records until mining threshold is reached.
pub struct UsageTracker {
    /// Accumulated records since last block.
    records: Vec<UsageRecord>,
    /// Per-user cumulative counts.
    per_user: HashMap<Address, UserUsage>,
    /// Total queries since last drain.
    total_queries: u64,
    /// Total tokens since last drain.
    total_tokens: u64,
    /// Total latency (for computing average).
    total_latency_ms: u64,
    /// Models seen.
    models: std::collections::HashSet<String>,
    /// Mining threshold.
    threshold: MiningThreshold,
}

impl UsageTracker {
    pub fn new(threshold: MiningThreshold) -> Self {
        Self {
            records: Vec::new(),
            per_user: HashMap::new(),
            total_queries: 0,
            total_tokens: 0,
            total_latency_ms: 0,
            models: std::collections::HashSet::new(),
            threshold,
        }
    }

    /// Record a completed query.
    /// SECURITY [D8]: Individual records are capped at MAX_RECORDS to prevent
    /// memory exhaustion if blocks can't be produced fast enough.
    pub fn record(&mut self, record: UsageRecord) {
        const MAX_RECORDS: usize = 100_000;

        let tokens = record.tokens_in as u64 + record.tokens_out as u64;
        self.total_queries += 1;
        self.total_tokens += tokens;
        self.total_latency_ms += record.latency_ms;
        self.models.insert(record.model.clone());

        let entry = self.per_user.entry(record.user).or_insert(UserUsage {
            queries: 0,
            tokens_in: 0,
            tokens_out: 0,
        });
        entry.queries += 1;
        entry.tokens_in += record.tokens_in as u64;
        entry.tokens_out += record.tokens_out as u64;

        // Keep individual records only up to capacity (counters still track everything)
        if self.records.len() < MAX_RECORDS {
            self.records.push(record);
        }
    }

    /// Check if the operator can mine a block.
    pub fn can_mine(&self) -> bool {
        self.total_queries >= self.threshold.min_queries
            || self.total_tokens >= self.threshold.min_tokens
    }

    /// Current query count since last drain.
    pub fn query_count(&self) -> u64 {
        self.total_queries
    }

    /// Current token count since last drain.
    pub fn token_count(&self) -> u64 {
        self.total_tokens
    }

    /// Number of unique users since last drain.
    pub fn unique_users(&self) -> usize {
        self.per_user.len()
    }

    /// Drain accumulated usage for block production. Resets all counters.
    pub fn drain_for_block(&mut self) -> UsageSummary {
        let avg_latency = if self.total_queries > 0 {
            self.total_latency_ms as f64 / self.total_queries as f64
        } else {
            0.0
        };

        let summary = UsageSummary {
            total_queries: self.total_queries,
            total_tokens: self.total_tokens,
            unique_users: self.per_user.len() as u32,
            per_user: self.per_user.clone(),
            models_served: self.models.iter().cloned().collect(),
            avg_latency_ms: avg_latency,
        };

        // Reset
        self.records.clear();
        self.per_user.clear();
        self.total_queries = 0;
        self.total_tokens = 0;
        self.total_latency_ms = 0;
        self.models.clear();

        summary
    }

    /// Progress toward mining threshold (0.0 - 1.0+).
    pub fn mining_progress(&self) -> f64 {
        let query_progress = self.total_queries as f64 / self.threshold.min_queries as f64;
        let token_progress = self.total_tokens as f64 / self.threshold.min_tokens as f64;
        query_progress.max(token_progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(user_byte: u8, tokens_in: u32, tokens_out: u32) -> UsageRecord {
        UsageRecord {
            user: Address::from([user_byte; 20]),
            model: "llama3.2:1b".to_string(),
            tokens_in,
            tokens_out,
            latency_ms: 100,
            timestamp: 0,
        }
    }

    #[test]
    fn test_empty_tracker() {
        let tracker = UsageTracker::new(MiningThreshold::default());
        assert!(!tracker.can_mine());
        assert_eq!(tracker.query_count(), 0);
        assert_eq!(tracker.token_count(), 0);
    }

    #[test]
    fn test_record_accumulation() {
        let mut tracker = UsageTracker::new(MiningThreshold::test_mode());
        tracker.record(make_record(1, 50, 100));
        tracker.record(make_record(2, 30, 80));
        assert_eq!(tracker.query_count(), 2);
        assert_eq!(tracker.token_count(), 260); // 50+100+30+80
        assert_eq!(tracker.unique_users(), 2);
    }

    #[test]
    fn test_mining_threshold_queries() {
        let mut tracker = UsageTracker::new(MiningThreshold {
            min_queries: 3,
            min_tokens: 1_000_000,
        });
        tracker.record(make_record(1, 10, 10));
        tracker.record(make_record(1, 10, 10));
        assert!(!tracker.can_mine());
        tracker.record(make_record(1, 10, 10));
        assert!(tracker.can_mine()); // 3 queries ≥ threshold
    }

    #[test]
    fn test_mining_threshold_tokens() {
        let mut tracker = UsageTracker::new(MiningThreshold {
            min_queries: 1_000_000,
            min_tokens: 50,
        });
        tracker.record(make_record(1, 20, 31));
        assert!(tracker.can_mine()); // 51 tokens ≥ 50 threshold
    }

    #[test]
    fn test_drain_resets() {
        let mut tracker = UsageTracker::new(MiningThreshold::test_mode());
        tracker.record(make_record(1, 50, 100));
        tracker.record(make_record(2, 30, 80));

        let summary = tracker.drain_for_block();
        assert_eq!(summary.total_queries, 2);
        assert_eq!(summary.total_tokens, 260);
        assert_eq!(summary.unique_users, 2);

        // After drain, counters reset
        assert_eq!(tracker.query_count(), 0);
        assert_eq!(tracker.token_count(), 0);
        assert!(!tracker.can_mine());
    }

    #[test]
    fn test_per_user_breakdown() {
        let mut tracker = UsageTracker::new(MiningThreshold::test_mode());
        tracker.record(make_record(1, 50, 100));
        tracker.record(make_record(1, 30, 80));
        tracker.record(make_record(2, 20, 40));

        let summary = tracker.drain_for_block();
        let user1 = &summary.per_user[&Address::from([1; 20])];
        assert_eq!(user1.queries, 2);
        assert_eq!(user1.tokens_in, 80);
        assert_eq!(user1.tokens_out, 180);
    }

    #[test]
    fn test_mining_progress() {
        let mut tracker = UsageTracker::new(MiningThreshold {
            min_queries: 10,
            min_tokens: 1000,
        });
        tracker.record(make_record(1, 25, 25)); // 1 query, 50 tokens
        assert!((tracker.mining_progress() - 0.1).abs() < 0.01); // 1/10 queries
    }
}
