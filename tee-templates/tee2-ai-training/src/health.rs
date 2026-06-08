//! Health monitoring and dynamic membership management.
//!
//! The HealthMonitor runs inside the TEE coordinator and tracks worker liveness
//! via heartbeats. It detects crashes, triggers rebalancing, and produces events
//! that the coordinator loop acts upon.

use alloy_primitives::Address;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::worker_state::{WorkerState, WorkerLifecycle, WorkerCapabilities, ResourceAllocation};
use crate::work_queue::WorkPartitioner;

/// Events produced by the health monitor for the coordinator to handle.
#[derive(Debug, Clone)]
pub enum RebalanceEvent {
    /// A new worker has registered and needs a shard assignment.
    WorkerJoined { operator: Address, capabilities: WorkerCapabilities },
    /// A worker has gracefully deregistered.
    WorkerLeft { operator: Address },
    /// A worker has stopped sending heartbeats (presumed crashed).
    WorkerCrashed { operator: Address, missed_heartbeats: u32 },
    /// A worker is significantly slower than peers.
    StragglerDetected { straggler: Address, throughput: f64, median_throughput: f64 },
}

/// Configuration for the health monitor.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between heartbeats (expected from workers).
    pub heartbeat_interval: Duration,
    /// Number of missed heartbeats before declaring a crash.
    pub max_missed_heartbeats: u32,
    /// How often the monitor checks for health issues.
    pub check_interval: Duration,
    /// Whether to auto-rebalance stragglers.
    pub auto_rebalance_stragglers: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(10),
            max_missed_heartbeats: 3,
            check_interval: Duration::from_secs(5),
            auto_rebalance_stragglers: true,
        }
    }
}

/// Monitors worker health and produces rebalance events.
pub struct HealthMonitor {
    config: HealthConfig,
    /// Pending events to be processed by the coordinator.
    pending_events: Vec<RebalanceEvent>,
    /// Last time a health check was performed.
    last_check: Instant,
}

impl HealthMonitor {
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            pending_events: Vec::new(),
            last_check: Instant::now(),
        }
    }

    /// Register a new worker. Produces a WorkerJoined event.
    pub fn register_worker(
        &mut self,
        operator: Address,
        capabilities: WorkerCapabilities,
        allocation: ResourceAllocation,
        workers: &mut HashMap<Address, WorkerState>,
    ) {
        if workers.contains_key(&operator) {
            // Worker reconnecting — update state
            if let Some(w) = workers.get_mut(&operator) {
                w.lifecycle = WorkerLifecycle::Pending;
                w.last_heartbeat = Instant::now();
                w.missed_heartbeats = 0;
                w.capabilities = capabilities.clone();
                w.allocation = allocation;
            }
        } else {
            workers.insert(operator, WorkerState::new(operator, capabilities.clone(), allocation));
        }

        self.pending_events.push(RebalanceEvent::WorkerJoined {
            operator,
            capabilities,
        });
    }

    /// Gracefully deregister a worker. Produces a WorkerLeft event.
    pub fn deregister_worker(
        &mut self,
        operator: &Address,
        workers: &mut HashMap<Address, WorkerState>,
    ) {
        if let Some(w) = workers.get_mut(operator) {
            w.lifecycle = WorkerLifecycle::Deregistered;
        }
        self.pending_events.push(RebalanceEvent::WorkerLeft {
            operator: *operator,
        });
    }

    /// Record a heartbeat from a worker.
    pub fn record_heartbeat(
        &self,
        operator: &Address,
        progress: f64,
        gpu_util: f64,
        workers: &mut HashMap<Address, WorkerState>,
    ) {
        if let Some(w) = workers.get_mut(operator) {
            w.record_heartbeat(progress, gpu_util);
            if w.lifecycle == WorkerLifecycle::Crashed {
                // Worker recovered — treat as reconnection
                w.lifecycle = WorkerLifecycle::Active;
            }
        }
    }

    /// Run a health check. Call this periodically (every check_interval).
    /// Returns events that occurred since the last check.
    pub fn check_health(
        &mut self,
        workers: &mut HashMap<Address, WorkerState>,
        partitioner: &WorkPartitioner,
    ) -> Vec<RebalanceEvent> {
        let timeout = self.config.heartbeat_interval * self.config.max_missed_heartbeats;
        let mut events = Vec::new();

        // Check for crashed workers
        for worker in workers.values_mut() {
            if worker.lifecycle == WorkerLifecycle::Deregistered || worker.lifecycle == WorkerLifecycle::Crashed {
                continue;
            }

            if worker.is_timed_out(timeout) {
                let elapsed = worker.last_heartbeat.elapsed();
                let missed = (elapsed.as_secs() / self.config.heartbeat_interval.as_secs().max(1)) as u32;
                worker.missed_heartbeats = missed;

                if missed >= self.config.max_missed_heartbeats && worker.lifecycle != WorkerLifecycle::Crashed {
                    worker.lifecycle = WorkerLifecycle::Crashed;
                    events.push(RebalanceEvent::WorkerCrashed {
                        operator: worker.operator,
                        missed_heartbeats: missed,
                    });
                }
            }
        }

        // Check for stragglers
        if self.config.auto_rebalance_stragglers {
            let stragglers = partitioner.detect_stragglers(workers);
            let throughputs: Vec<f64> = workers.values()
                .filter(|w| w.assigned_shard.is_some())
                .map(|w| w.avg_throughput())
                .collect();

            if throughputs.len() >= 3 {
                let mut sorted = throughputs.clone();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let median = sorted[sorted.len() / 2];

                for straggler_addr in stragglers {
                    if let Some(w) = workers.get_mut(&straggler_addr) {
                        w.lifecycle = WorkerLifecycle::Straggler;
                        events.push(RebalanceEvent::StragglerDetected {
                            straggler: straggler_addr,
                            throughput: w.avg_throughput(),
                            median_throughput: median,
                        });
                    }
                }
            }
        }

        // Drain any pending events from register/deregister calls
        events.extend(self.pending_events.drain(..));
        self.last_check = Instant::now();

        events
    }

    /// Get the number of active (non-crashed, non-deregistered) workers.
    pub fn active_worker_count(workers: &HashMap<Address, WorkerState>) -> usize {
        workers.values().filter(|w| {
            w.lifecycle == WorkerLifecycle::Active
                || w.lifecycle == WorkerLifecycle::Pending
                || w.lifecycle == WorkerLifecycle::Straggler
        }).count()
    }
}

/// Shard checkpoint for crash recovery.
/// Stored in-memory by the coordinator after each completed generation.
#[derive(Debug, Clone)]
pub struct ShardCheckpoint {
    pub shard_id: usize,
    pub generation: u64,
    pub population_start: usize,
    pub population_end: usize,
    pub best_fitness: f64,
    pub timestamp: Instant,
}

/// Checkpoint manager: stores and retrieves generation checkpoints.
pub struct CheckpointManager {
    /// Generation → list of shard checkpoints.
    checkpoints: HashMap<u64, Vec<ShardCheckpoint>>,
    /// Maximum number of generations to retain.
    max_retained: usize,
}

impl CheckpointManager {
    pub fn new(max_retained: usize) -> Self {
        Self {
            checkpoints: HashMap::new(),
            max_retained,
        }
    }

    /// Save a checkpoint for a completed shard.
    pub fn save_checkpoint(&mut self, checkpoint: ShardCheckpoint) {
        self.checkpoints
            .entry(checkpoint.generation)
            .or_default()
            .push(checkpoint);

        // Prune old checkpoints
        if self.checkpoints.len() > self.max_retained {
            let min_gen = *self.checkpoints.keys().min().unwrap_or(&0);
            self.checkpoints.remove(&min_gen);
        }
    }

    /// Get the last complete checkpoint (all shards reported).
    pub fn last_complete_checkpoint(&self, expected_shards: usize) -> Option<u64> {
        self.checkpoints.iter()
            .filter(|(_, shards)| shards.len() >= expected_shards)
            .map(|(gen, _)| *gen)
            .max()
    }

    /// Get checkpoints for a specific generation.
    pub fn get_checkpoints(&self, generation: u64) -> Option<&Vec<ShardCheckpoint>> {
        self.checkpoints.get(&generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_state::{WorkerCapabilities, ResourceAllocation};

    #[test]
    fn test_crash_detection() {
        let config = HealthConfig {
            heartbeat_interval: Duration::from_secs(10),
            max_missed_heartbeats: 3,
            check_interval: Duration::from_secs(5),
            auto_rebalance_stragglers: false,
        };
        let mut monitor = HealthMonitor::new(config);
        let mut workers = HashMap::new();
        let partitioner = WorkPartitioner::new(1000);

        let addr = Address::from([0x01; 20]);
        monitor.register_worker(addr, WorkerCapabilities::default(), ResourceAllocation::full(), &mut workers);

        // Simulate crash by setting last_heartbeat to the past
        workers.get_mut(&addr).unwrap().last_heartbeat = Instant::now() - Duration::from_secs(60);
        workers.get_mut(&addr).unwrap().lifecycle = WorkerLifecycle::Active;

        let events = monitor.check_health(&mut workers, &partitioner);

        let crash_events: Vec<_> = events.iter()
            .filter(|e| matches!(e, RebalanceEvent::WorkerCrashed { .. }))
            .collect();
        assert!(!crash_events.is_empty(), "Should detect crashed worker");
        assert_eq!(workers[&addr].lifecycle, WorkerLifecycle::Crashed);
    }

    #[test]
    fn test_graceful_leave() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);
        let mut workers = HashMap::new();

        let addr = Address::from([0x01; 20]);
        monitor.register_worker(addr, WorkerCapabilities::default(), ResourceAllocation::full(), &mut workers);
        monitor.deregister_worker(&addr, &mut workers);

        assert_eq!(workers[&addr].lifecycle, WorkerLifecycle::Deregistered);
    }

    #[test]
    fn test_checkpoint_pruning() {
        let mut mgr = CheckpointManager::new(3);
        for gen in 0..5 {
            mgr.save_checkpoint(ShardCheckpoint {
                shard_id: 0, generation: gen,
                population_start: 0, population_end: 1000,
                best_fitness: gen as f64, timestamp: Instant::now(),
            });
        }
        // Should retain at most 3 generations
        assert!(mgr.checkpoints.len() <= 3);
    }
}
