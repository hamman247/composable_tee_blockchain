//! Ethereum validator node simulation.
//!
//! Tracks active validators, epoch duties, and performance metrics.

use serde::{Deserialize, Serialize};

/// Validator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Beacon chain endpoint (simulation: unused).
    pub beacon_url: String,
    /// Execution layer endpoint.
    pub execution_url: String,
}

impl ValidatorConfig {
    pub fn test_mode() -> Self {
        Self {
            beacon_url: "http://localhost:5052".into(),
            execution_url: "http://localhost:8545".into(),
        }
    }
}

/// Status of an individual validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    PendingActivation,
    Active,
    Exiting,
    Exited,
}

/// Simulated validator node.
pub struct ValidatorNode {
    #[allow(dead_code)]
    config: ValidatorConfig,
    validators: Vec<ValidatorStatus>,
    last_epoch: u64,
}

impl ValidatorNode {
    pub fn new(config: ValidatorConfig) -> Self {
        Self { config, validators: Vec::new(), last_epoch: 0 }
    }

    /// Add a new validator (activated immediately in simulation).
    pub fn add_validator(&mut self) {
        self.validators.push(ValidatorStatus::Active);
    }

    /// Number of active validators.
    pub fn active_count(&self) -> u32 {
        self.validators.iter().filter(|v| **v == ValidatorStatus::Active).count() as u32
    }

    /// Total validators (all statuses).
    pub fn total_count(&self) -> u32 {
        self.validators.len() as u32
    }

    /// Record an epoch processed.
    pub fn record_epoch(&mut self, epoch: u64) {
        self.last_epoch = epoch;
    }

    /// Exit a validator.
    pub fn exit_validator(&mut self, index: usize) -> bool {
        if index < self.validators.len() && self.validators[index] == ValidatorStatus::Active {
            self.validators[index] = ValidatorStatus::Exited;
            true
        } else {
            false
        }
    }

    /// SECURITY [D5]: Remove all Exited validators to prevent unbounded accumulation.
    /// Should be called periodically (e.g., every 100 epochs).
    pub fn compact_exited(&mut self) -> usize {
        let before = self.validators.len();
        self.validators.retain(|v| *v != ValidatorStatus::Exited);
        before - self.validators.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_count() {
        let mut node = ValidatorNode::new(ValidatorConfig::test_mode());
        assert_eq!(node.active_count(), 0);
        node.add_validator();
        node.add_validator();
        assert_eq!(node.active_count(), 2);
        assert_eq!(node.total_count(), 2);
    }

    #[test]
    fn test_exit_validator() {
        let mut node = ValidatorNode::new(ValidatorConfig::test_mode());
        node.add_validator();
        node.add_validator();
        assert!(node.exit_validator(0));
        assert_eq!(node.active_count(), 1);
        assert_eq!(node.total_count(), 2);
    }

    #[test]
    fn test_exit_invalid_index() {
        let mut node = ValidatorNode::new(ValidatorConfig::test_mode());
        assert!(!node.exit_validator(0)); // no validators
    }

    #[test]
    fn test_record_epoch() {
        let mut node = ValidatorNode::new(ValidatorConfig::test_mode());
        node.record_epoch(100);
        assert_eq!(node.last_epoch, 100);
    }
}
