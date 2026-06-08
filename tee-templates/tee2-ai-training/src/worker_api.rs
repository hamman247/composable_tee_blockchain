//! Worker-facing API for the TEE-2 coordinator.
//!
//! Workers connect to the coordinator via JSON-RPC (using the same jsonrpsee
//! infrastructure as the main node). All requests are authenticated — the
//! worker must provide its operator address.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::worker_state::{WorkerCapabilities, ResourceAllocation};
use crate::work_queue::WorkAssignment;

/// Request to register as a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWorkerRequest {
    /// Operator address (must be registered on-chain).
    pub operator: Address,
    /// Hardware capabilities.
    pub capabilities: WorkerCapabilities,
    /// Resource allocation — how much processing power to dedicate.
    /// Defaults to full (100%) if not specified.
    pub allocation: Option<ResourceAllocation>,
    /// Worker's listen address for coordinator callbacks.
    pub callback_address: Option<String>,
}

/// Response to worker registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWorkerResponse {
    /// Whether registration was accepted.
    pub accepted: bool,
    /// Assigned shard index (if immediately assigned).
    pub shard_id: Option<usize>,
    /// Current generation number.
    pub generation: u64,
    /// Heartbeat interval the worker should use.
    pub heartbeat_interval_secs: u64,
    /// The effective allocation applied.
    pub effective_allocation: f64,
    /// The effective weight used for shard sizing.
    pub effective_weight: f64,
    /// Reason if rejected.
    pub rejection_reason: Option<String>,
}

/// Request to update resource allocation at runtime.
/// This allows node operators to scale up or down without re-registering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAllocationRequest {
    pub operator: Address,
    /// New resource allocation.
    pub allocation: ResourceAllocation,
}

/// Response to allocation update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAllocationResponse {
    /// Whether the update was accepted.
    pub accepted: bool,
    /// The new effective weight.
    pub new_effective_weight: f64,
    /// The new allocation fraction.
    pub new_allocation: f64,
    /// Whether a shard rebalance was triggered.
    pub rebalance_triggered: bool,
}

/// Heartbeat message from worker to coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub operator: Address,
    /// Progress through current shard (0.0 - 1.0).
    pub shard_progress: f64,
    /// GPU utilization (0.0 - 1.0).
    pub gpu_utilization: f64,
    /// Current generation being processed.
    pub generation: u64,
    /// Estimated seconds to complete current work.
    pub eta_seconds: Option<u64>,
}

/// Heartbeat acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Whether the worker should continue current work.
    pub continue_work: bool,
    /// If non-empty, worker should abort current work and take new assignment.
    pub new_assignment: Option<WorkAssignment>,
    /// Coordinator's current generation (worker can detect if it's behind).
    pub coordinator_generation: u64,
}

/// Request to deregister gracefully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeregisterRequest {
    pub operator: Address,
}

/// Request to get work assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetWorkRequest {
    pub operator: Address,
}

/// Response to work submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitWorkResponse {
    /// Whether the result was accepted.
    pub accepted: bool,
    /// Next work assignment (if available).
    pub next_assignment: Option<WorkAssignment>,
    /// Compute units credited for this submission.
    pub credited_compute_units: u64,
}

/// Per-operator reward breakdown (included in block data for transparency).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRewardBreakdown {
    pub operator: Address,
    /// Compute units contributed this round.
    pub compute_units: u64,
    /// Proportion of total compute (0.0 - 1.0).
    pub proportion: f64,
    /// Reward amount in wei.
    pub reward_wei: String,
    /// Resource allocation fraction.
    pub allocation: f64,
    /// Hardware weight (pre-allocation).
    pub raw_weight: f64,
    /// Effective weight (post-allocation).
    pub effective_weight: f64,
}

/// Coordinator status (public, no auth required).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStatus {
    /// Current mode (Training/Inference).
    pub mode: String,
    /// Number of active workers.
    pub active_workers: usize,
    /// Total registered workers (including crashed/deregistered).
    pub total_workers: usize,
    /// Current generation.
    pub generation: u64,
    /// Number of shards.
    pub num_shards: usize,
    /// Best fitness score across all shards.
    pub best_fitness: f64,
    /// Total compute units accumulated this round.
    pub total_compute_units: u64,
    /// Total effective weight across all active workers.
    pub total_effective_weight: f64,
    /// Blocks produced so far.
    pub blocks_produced: u64,
    /// Per-worker allocation breakdown.
    pub worker_allocations: Vec<WorkerAllocationInfo>,
}

/// Public info about a worker's allocation (for status queries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerAllocationInfo {
    pub operator: Address,
    pub allocation_pct: f64,
    pub effective_weight: f64,
    pub compute_units_this_round: u64,
    pub lifecycle: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_request_serialization() {
        let req = RegisterWorkerRequest {
            operator: Address::from([0x01; 20]),
            capabilities: WorkerCapabilities::default(),
            allocation: Some(ResourceAllocation::new(0.5)),
            callback_address: Some("ws://worker:9000".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: RegisterWorkerRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.operator, req.operator);
        assert!((decoded.allocation.unwrap().fraction - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_update_allocation_serialization() {
        let req = UpdateAllocationRequest {
            operator: Address::from([0x01; 20]),
            allocation: ResourceAllocation::new(0.75),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: UpdateAllocationRequest = serde_json::from_str(&json).unwrap();
        assert!((decoded.allocation.fraction - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coordinator_status_serialization() {
        let status = CoordinatorStatus {
            mode: "Training".to_string(),
            active_workers: 5,
            total_workers: 7,
            generation: 42,
            num_shards: 5,
            best_fitness: 0.987,
            total_compute_units: 1_000_000,
            total_effective_weight: 120.0,
            blocks_produced: 3,
            worker_allocations: vec![],
        };
        let json = serde_json::to_string_pretty(&status).unwrap();
        assert!(json.contains("Training"));
    }
}
