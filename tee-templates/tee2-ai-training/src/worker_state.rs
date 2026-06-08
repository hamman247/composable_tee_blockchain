//! Worker state tracking for TEE-2 coordinator.
//!
//! Each worker node is identified by its operator address and tracked
//! through its lifecycle: registration → active → (optional) straggler → deregistered/crashed.
//!
//! ## Resource Allocation
//!
//! Node operators choose how much of their hardware to dedicate to training
//! via the `resource_allocation` field (0.0 - 1.0). This controls:
//! - **Shard sizing**: Allocation scales the effective weight, so a 50% allocation
//!   gets roughly half the shard of a full allocation with the same hardware
//! - **Reward proportionality**: Rewards are proportional to actual compute delivered,
//!   which naturally correlates with allocation level

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Hardware capabilities declared by a worker at registration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    /// Number of CPU cores available for training.
    pub cpu_cores: u32,
    /// Number of GPUs available.
    pub gpu_count: u32,
    /// GPU memory in MiB per device.
    pub gpu_memory_mib: u64,
    /// System RAM in MiB.
    pub ram_mib: u64,
    /// Self-reported compute benchmark score (optional, verified by TEE).
    pub benchmark_score: Option<u64>,
}

impl WorkerCapabilities {
    /// Compute raw hardware weight (before resource allocation scaling).
    /// GPU-heavy workers get proportionally larger shards.
    pub fn raw_weight(&self) -> f64 {
        let cpu_weight = self.cpu_cores as f64;
        let gpu_weight = self.gpu_count as f64 * 10.0; // GPUs weighted 10x
        let mem_factor = (self.gpu_memory_mib as f64 / 8192.0).min(4.0).max(1.0);
        (cpu_weight + gpu_weight) * mem_factor
    }

    /// Compute effective weight factoring in the operator's resource allocation.
    /// `allocation` is clamped to [0.01, 1.0] — 0% allocation is not permitted.
    pub fn weight(&self, allocation: f64) -> f64 {
        let clamped = allocation.clamp(0.01, 1.0);
        self.raw_weight() * clamped
    }
}

impl Default for WorkerCapabilities {
    fn default() -> Self {
        Self {
            cpu_cores: 4,
            gpu_count: 1,
            gpu_memory_mib: 8192,
            ram_mib: 16384,
            benchmark_score: None,
        }
    }
}

/// Resource allocation configuration chosen by the node operator.
/// This determines how much processing power the operator dedicates to this TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    /// Fraction of total hardware to dedicate (0.01 - 1.0).
    /// 1.0 = all resources, 0.5 = half resources, 0.1 = 10%, etc.
    pub fraction: f64,
    /// Optional: max CPU cores to use (overrides fraction for CPU if set).
    pub max_cpu_cores: Option<u32>,
    /// Optional: max GPUs to use (overrides fraction for GPU if set).
    pub max_gpus: Option<u32>,
    /// Optional: max RAM in MiB to use.
    pub max_ram_mib: Option<u64>,
}

impl ResourceAllocation {
    /// Create an allocation with the given fraction (clamped to [0.01, 1.0]).
    pub fn new(fraction: f64) -> Self {
        Self {
            fraction: fraction.clamp(0.01, 1.0),
            max_cpu_cores: None,
            max_gpus: None,
            max_ram_mib: None,
        }
    }

    /// Full allocation — dedicate all available hardware.
    pub fn full() -> Self {
        Self::new(1.0)
    }

    /// Compute the effective capabilities after applying this allocation.
    pub fn effective_capabilities(&self, hardware: &WorkerCapabilities) -> WorkerCapabilities {
        let f = self.fraction.clamp(0.01, 1.0);
        WorkerCapabilities {
            cpu_cores: self.max_cpu_cores
                .unwrap_or((hardware.cpu_cores as f64 * f).ceil() as u32)
                .min(hardware.cpu_cores)
                .max(1),
            gpu_count: self.max_gpus
                .unwrap_or((hardware.gpu_count as f64 * f).ceil() as u32)
                .min(hardware.gpu_count),
            gpu_memory_mib: self.max_ram_mib
                .map(|m| m.min(hardware.gpu_memory_mib))
                .unwrap_or((hardware.gpu_memory_mib as f64 * f) as u64),
            ram_mib: (hardware.ram_mib as f64 * f) as u64,
            benchmark_score: hardware.benchmark_score.map(|s| (s as f64 * f) as u64),
        }
    }

    /// Effective fraction as a percentage string.
    pub fn percentage(&self) -> String {
        format!("{:.0}%", self.fraction * 100.0)
    }
}

impl Default for ResourceAllocation {
    fn default() -> Self {
        Self::full()
    }
}

/// Lifecycle state of a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerLifecycle {
    /// Worker has registered but hasn't received work yet.
    Pending,
    /// Worker is actively processing a shard.
    Active,
    /// Worker is significantly slower than peers (>2x median).
    Straggler,
    /// Worker gracefully deregistered.
    Deregistered,
    /// Worker stopped sending heartbeats (presumed crashed).
    Crashed,
}

/// Full state of a connected worker, maintained by the coordinator.
#[derive(Debug, Clone)]
pub struct WorkerState {
    /// Operator address (also used as unique worker ID).
    pub operator: Address,
    /// Full hardware capabilities declared at registration.
    pub capabilities: WorkerCapabilities,
    /// Operator-chosen resource allocation (how much of their hardware to dedicate).
    pub allocation: ResourceAllocation,
    /// Current lifecycle state.
    pub lifecycle: WorkerLifecycle,
    /// Assigned shard index (None if pending or deregistered).
    pub assigned_shard: Option<usize>,
    /// Last heartbeat received.
    pub last_heartbeat: Instant,
    /// Number of consecutive missed heartbeats.
    pub missed_heartbeats: u32,
    /// Current generation the worker is processing.
    pub current_generation: u64,
    /// Self-reported progress through current shard (0.0 - 1.0).
    pub shard_progress: f64,
    /// Self-reported GPU utilization (0.0 - 1.0).
    pub gpu_utilization: f64,
    /// Historical throughput: compute units delivered per second (rolling average).
    pub throughput_history: Vec<f64>,
    /// Total compute units contributed across all rounds.
    pub total_compute_units: u64,
    /// Compute units contributed in the current round.
    pub round_compute_units: u64,
    /// When this worker registered.
    pub registered_at: Instant,
}

impl WorkerState {
    pub fn new(operator: Address, capabilities: WorkerCapabilities, allocation: ResourceAllocation) -> Self {
        Self {
            operator,
            capabilities,
            allocation,
            lifecycle: WorkerLifecycle::Pending,
            assigned_shard: None,
            last_heartbeat: Instant::now(),
            missed_heartbeats: 0,
            current_generation: 0,
            shard_progress: 0.0,
            gpu_utilization: 0.0,
            throughput_history: Vec::new(),
            total_compute_units: 0,
            round_compute_units: 0,
            registered_at: Instant::now(),
        }
    }

    /// Get the effective weight for shard sizing (hardware × allocation).
    pub fn effective_weight(&self) -> f64 {
        self.capabilities.weight(self.allocation.fraction)
    }

    /// Get the effective capabilities after applying the allocation.
    pub fn effective_capabilities(&self) -> WorkerCapabilities {
        self.allocation.effective_capabilities(&self.capabilities)
    }

    /// Update the resource allocation. Returns the new effective weight.
    pub fn update_allocation(&mut self, new_allocation: ResourceAllocation) -> f64 {
        self.allocation = new_allocation;
        self.effective_weight()
    }

    /// Record a heartbeat from this worker.
    pub fn record_heartbeat(&mut self, progress: f64, gpu_util: f64) {
        self.last_heartbeat = Instant::now();
        self.missed_heartbeats = 0;
        self.shard_progress = progress;
        self.gpu_utilization = gpu_util;
    }

    /// Check if this worker has timed out (missed too many heartbeats).
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_heartbeat.elapsed() > timeout
    }

    /// Record throughput measurement and update rolling average.
    pub fn record_throughput(&mut self, compute_units_per_sec: f64) {
        self.throughput_history.push(compute_units_per_sec);
        // Keep last 10 measurements
        if self.throughput_history.len() > 10 {
            self.throughput_history.remove(0);
        }
    }

    /// Get average throughput.
    pub fn avg_throughput(&self) -> f64 {
        if self.throughput_history.is_empty() {
            return 0.0;
        }
        self.throughput_history.iter().sum::<f64>() / self.throughput_history.len() as f64
    }

    /// Record compute units contributed.
    pub fn add_compute(&mut self, units: u64) {
        self.total_compute_units += units;
        self.round_compute_units += units;
    }

    /// Reset round compute counter (called at block production).
    pub fn reset_round_compute(&mut self) {
        self.round_compute_units = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_capabilities_weight_with_allocation() {
        let caps = WorkerCapabilities {
            cpu_cores: 8, gpu_count: 2, gpu_memory_mib: 16384, ram_mib: 32768,
            benchmark_score: None,
        };
        let full = caps.weight(1.0);
        let half = caps.weight(0.5);
        let quarter = caps.weight(0.25);

        // Half allocation should give half the weight
        assert!((half - full * 0.5).abs() < 0.01);
        assert!((quarter - full * 0.25).abs() < 0.01);
    }

    #[test]
    fn test_allocation_clamps_to_minimum() {
        let alloc = ResourceAllocation::new(0.0);
        assert!((alloc.fraction - 0.01).abs() < f64::EPSILON);

        let alloc_neg = ResourceAllocation::new(-1.0);
        assert!((alloc_neg.fraction - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_effective_capabilities() {
        let hardware = WorkerCapabilities {
            cpu_cores: 16, gpu_count: 4, gpu_memory_mib: 32768, ram_mib: 65536,
            benchmark_score: Some(10000),
        };
        let alloc = ResourceAllocation::new(0.5);
        let effective = alloc.effective_capabilities(&hardware);

        assert_eq!(effective.cpu_cores, 8);    // 16 * 0.5
        assert_eq!(effective.gpu_count, 2);     // 4 * 0.5
        assert_eq!(effective.ram_mib, 32768);   // 65536 * 0.5
    }

    #[test]
    fn test_effective_capabilities_with_max_overrides() {
        let hardware = WorkerCapabilities {
            cpu_cores: 16, gpu_count: 4, gpu_memory_mib: 32768, ram_mib: 65536,
            benchmark_score: None,
        };
        let alloc = ResourceAllocation {
            fraction: 1.0,
            max_cpu_cores: Some(4),   // Only use 4 of 16 cores
            max_gpus: Some(1),         // Only use 1 of 4 GPUs
            max_ram_mib: None,
        };
        let effective = alloc.effective_capabilities(&hardware);

        assert_eq!(effective.cpu_cores, 4);
        assert_eq!(effective.gpu_count, 1);
    }

    #[test]
    fn test_proportional_weight() {
        let caps_a = WorkerCapabilities {
            cpu_cores: 8, gpu_count: 4, gpu_memory_mib: 16384, ram_mib: 32768,
            benchmark_score: None,
        };
        let caps_b = caps_a.clone();

        // Worker A at 100%, Worker B at 25%
        let weight_a = caps_a.weight(1.0);
        let weight_b = caps_b.weight(0.25);

        // Worker A should get 4x the shard of Worker B
        let ratio = weight_a / weight_b;
        assert!((ratio - 4.0).abs() < 0.01);
    }

    #[test]
    fn test_heartbeat_timeout() {
        let mut worker = WorkerState::new(Address::ZERO, WorkerCapabilities::default(), ResourceAllocation::full());
        assert!(!worker.is_timed_out(Duration::from_secs(30)));
        worker.last_heartbeat = Instant::now() - Duration::from_secs(60);
        assert!(worker.is_timed_out(Duration::from_secs(30)));
    }

    #[test]
    fn test_throughput_rolling_average() {
        let mut worker = WorkerState::new(Address::ZERO, WorkerCapabilities::default(), ResourceAllocation::full());
        for i in 1..=15 {
            worker.record_throughput(i as f64 * 100.0);
        }
        assert_eq!(worker.throughput_history.len(), 10);
        let avg = worker.avg_throughput();
        assert!(avg > 1000.0 && avg < 1100.0);
    }

    #[test]
    fn test_round_compute_tracking() {
        let mut worker = WorkerState::new(Address::ZERO, WorkerCapabilities::default(), ResourceAllocation::full());
        worker.add_compute(1000);
        worker.add_compute(500);
        assert_eq!(worker.round_compute_units, 1500);
        assert_eq!(worker.total_compute_units, 1500);

        worker.reset_round_compute();
        assert_eq!(worker.round_compute_units, 0);
        assert_eq!(worker.total_compute_units, 1500); // Total not reset
    }
}
