//! Work partitioning and shard management for distributed genetic algorithm training.
//!
//! The coordinator splits the total population of candidate models into shards,
//! assigns each shard to a worker, and manages inter-shard migration of top candidates.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::worker_state::WorkerState;

/// A shard of the total population assigned to one worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    /// Unique shard index.
    pub shard_id: usize,
    /// Operator address of the worker assigned to this shard.
    pub assigned_to: Option<Address>,
    /// Start index in the global population (inclusive).
    pub population_start: usize,
    /// End index in the global population (exclusive).
    pub population_end: usize,
    /// Current generation number for this shard.
    pub generation: u64,
    /// Whether this shard is orphaned (worker crashed).
    pub orphaned: bool,
    /// Best fitness score seen in this shard.
    pub best_fitness: f64,
}

impl Shard {
    pub fn size(&self) -> usize {
        self.population_end - self.population_start
    }

    /// Split this shard at the midpoint, returning the new (second half) shard.
    pub fn split(&mut self, new_shard_id: usize) -> Shard {
        let mid = self.population_start + self.size() / 2;
        let new_shard = Shard {
            shard_id: new_shard_id,
            assigned_to: None,
            population_start: mid,
            population_end: self.population_end,
            generation: self.generation,
            orphaned: false,
            best_fitness: 0.0,
        };
        self.population_end = mid;
        new_shard
    }

    /// Merge another shard into this one.
    /// The orphan's population is logically appended to this shard's range.
    /// This works because population indices are abstract slots — contiguity
    /// of the original ranges doesn't matter for the genetic algorithm.
    pub fn merge(&mut self, other: &Shard) {
        // Extend this shard to cover the orphan's population by growing the end.
        self.population_end += other.size();
    }
}

/// Work assignment sent to a worker for one generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkAssignment {
    /// Shard the worker should process.
    pub shard_id: usize,
    /// Generation number to process.
    pub generation: u64,
    /// Population range (start..end indices).
    pub population_start: usize,
    pub population_end: usize,
    /// Candidate models migrated in from other shards.
    pub migrants: Vec<Candidate>,
    /// Training hyperparameters for this generation.
    pub hyperparams: TrainingHyperparams,
}

/// Result submitted by a worker after completing one generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkResult {
    /// Shard that was processed.
    pub shard_id: usize,
    /// Generation that was completed.
    pub generation: u64,
    /// Operator address of the worker.
    pub operator: Address,
    /// Top N candidates (for migration to other shards).
    pub top_candidates: Vec<Candidate>,
    /// Fitness scores for the entire shard population.
    pub fitness_scores: FitnessReport,
    /// Compute metrics for reward calculation.
    pub compute_metrics: ComputeMetrics,
}

/// A candidate model (simplified representation for the protocol layer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// Global index in the population.
    pub index: usize,
    /// Fitness score.
    pub fitness: f64,
    /// Model parameters (opaque bytes — could be weights, hyperparams, etc.).
    pub parameters: Vec<u8>,
}

/// Fitness report for a shard's population.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitnessReport {
    pub best_fitness: f64,
    pub worst_fitness: f64,
    pub mean_fitness: f64,
    pub median_fitness: f64,
    pub population_evaluated: usize,
}

/// Compute metrics reported by a worker (used for reward calculation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeMetrics {
    /// CPU cycles spent on evaluation.
    pub cpu_cycles: u64,
    /// GPU cycles spent on evaluation.
    pub gpu_cycles: u64,
    /// Wall-clock time in milliseconds.
    pub wall_time_ms: u64,
    /// Number of candidate evaluations performed.
    pub evaluations: u64,
}

/// Training hyperparameters sent to workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingHyperparams {
    /// Mutation rate (0.0 - 1.0).
    pub mutation_rate: f64,
    /// Crossover rate (0.0 - 1.0).
    pub crossover_rate: f64,
    /// Tournament selection size.
    pub tournament_size: usize,
    /// Elite count (top N candidates preserved without mutation).
    pub elite_count: usize,
}

impl Default for TrainingHyperparams {
    fn default() -> Self {
        Self {
            mutation_rate: 0.1,
            crossover_rate: 0.7,
            tournament_size: 5,
            elite_count: 10,
        }
    }
}

/// Manages population sharding, assignment, and inter-shard migration.
pub struct WorkPartitioner {
    /// Total population size.
    pub total_population: usize,
    /// All shards.
    pub shards: Vec<Shard>,
    /// Current generation.
    pub generation: u64,
    /// Migration rate: fraction of top candidates exchanged between shards.
    pub migration_rate: f64,
    /// Migration buffer: top candidates collected from completed shards.
    migration_buffer: Vec<Candidate>,
    /// Next shard ID to assign.
    next_shard_id: usize,
    /// Hyperparameters for the current generation.
    pub hyperparams: TrainingHyperparams,
}

impl WorkPartitioner {
    /// Create a new partitioner for the given population size.
    pub fn new(total_population: usize) -> Self {
        Self {
            total_population,
            shards: Vec::new(),
            generation: 0,
            migration_rate: 0.10, // 10% migration
            migration_buffer: Vec::new(),
            next_shard_id: 0,
            hyperparams: TrainingHyperparams::default(),
        }
    }

    /// Initial partitioning: create shards for a set of workers, weighted by capability.
    pub fn partition_for_workers(&mut self, workers: &HashMap<Address, WorkerState>) {
        self.shards.clear();
        self.next_shard_id = 0;

        if workers.is_empty() {
            return;
        }

        // Calculate total weight (hardware × operator allocation)
        let total_weight: f64 = workers.values()
            .map(|w| w.effective_weight())
            .sum();

        let mut offset = 0;
        let worker_list: Vec<&WorkerState> = workers.values().collect();

        for (i, worker) in worker_list.iter().enumerate() {
            let weight = worker.effective_weight();
            let fraction = weight / total_weight;

            // Last worker gets any remaining population to avoid rounding gaps
            let shard_size = if i == worker_list.len() - 1 {
                self.total_population - offset
            } else {
                (self.total_population as f64 * fraction).round() as usize
            };

            if shard_size == 0 {
                continue;
            }

            let shard = Shard {
                shard_id: self.next_shard_id,
                assigned_to: Some(worker.operator),
                population_start: offset,
                population_end: offset + shard_size,
                generation: self.generation,
                orphaned: false,
                best_fitness: 0.0,
            };

            self.shards.push(shard);
            self.next_shard_id += 1;
            offset += shard_size;
        }
    }

    /// Get the work assignment for a specific worker.
    pub fn get_assignment(&self, operator: &Address) -> Option<WorkAssignment> {
        let shard = self.shards.iter().find(|s| s.assigned_to.as_ref() == Some(operator))?;

        // Select migrants for this shard (from the migration buffer, excluding own candidates)
        let migrants: Vec<Candidate> = self.migration_buffer.iter()
            .filter(|c| c.index < shard.population_start || c.index >= shard.population_end)
            .cloned()
            .collect();

        Some(WorkAssignment {
            shard_id: shard.shard_id,
            generation: self.generation,
            population_start: shard.population_start,
            population_end: shard.population_end,
            migrants,
            hyperparams: self.hyperparams.clone(),
        })
    }

    /// Process a work result from a worker.
    pub fn submit_result(&mut self, result: &WorkResult) {
        // Update shard fitness
        if let Some(shard) = self.shards.iter_mut().find(|s| s.shard_id == result.shard_id) {
            shard.best_fitness = result.fitness_scores.best_fitness;
        }

        // Collect top candidates for migration
        let migration_count = (result.top_candidates.len() as f64 * self.migration_rate).ceil() as usize;
        let migrants: Vec<Candidate> = result.top_candidates.iter()
            .take(migration_count)
            .cloned()
            .collect();
        self.migration_buffer.extend(migrants);
    }

    /// Advance to the next generation. Clears migration buffer.
    pub fn advance_generation(&mut self) {
        self.generation += 1;
        self.migration_buffer.clear();
        for shard in &mut self.shards {
            shard.generation = self.generation;
        }
    }

    /// Handle a new worker joining: split the largest shard.
    pub fn add_worker(&mut self, operator: Address) -> Option<usize> {
        if self.shards.is_empty() {
            // First worker gets the entire population
            let shard = Shard {
                shard_id: self.next_shard_id,
                assigned_to: Some(operator),
                population_start: 0,
                population_end: self.total_population,
                generation: self.generation,
                orphaned: false,
                best_fitness: 0.0,
            };
            self.next_shard_id += 1;
            self.shards.push(shard);
            return Some(self.shards.len() - 1);
        }

        // Find the largest shard and split it
        let largest_idx = self.shards.iter()
            .enumerate()
            .filter(|(_, s)| !s.orphaned && s.size() > 1)
            .max_by_key(|(_, s)| s.size())
            .map(|(i, _)| i)?;

        let new_shard_id = self.next_shard_id;
        self.next_shard_id += 1;

        let mut new_shard = self.shards[largest_idx].split(new_shard_id);
        new_shard.assigned_to = Some(operator);
        self.shards.push(new_shard);

        Some(self.shards.len() - 1)
    }

    /// Handle a worker leaving or crashing: orphan its shard and redistribute.
    pub fn remove_worker(&mut self, operator: &Address) {
        // Mark the worker's shard as orphaned
        let orphaned_idx = self.shards.iter().position(|s| s.assigned_to.as_ref() == Some(operator));

        if let Some(idx) = orphaned_idx {
            self.shards[idx].orphaned = true;
            self.shards[idx].assigned_to = None;
        }

        self.redistribute_orphans();
    }

    /// Redistribute orphaned shards across remaining active workers.
    fn redistribute_orphans(&mut self) {
        let orphaned: Vec<Shard> = self.shards.iter()
            .filter(|s| s.orphaned)
            .cloned()
            .collect();

        if orphaned.is_empty() {
            return;
        }

        // Find active shards to absorb the orphans
        let active_count = self.shards.iter().filter(|s| !s.orphaned && s.assigned_to.is_some()).count();
        if active_count == 0 {
            return; // No active workers to redistribute to
        }

        // Merge each orphan into the smallest active shard
        for orphan in &orphaned {
            let smallest_active = self.shards.iter_mut()
                .filter(|s| !s.orphaned && s.assigned_to.is_some())
                .min_by_key(|s| s.size());

            if let Some(target) = smallest_active {
                target.merge(orphan);
            }
        }

        // Remove orphaned shards
        self.shards.retain(|s| !s.orphaned);
    }

    /// Detect stragglers: workers whose throughput is < 50% of the median.
    pub fn detect_stragglers(&self, workers: &HashMap<Address, WorkerState>) -> Vec<Address> {
        let mut throughputs: Vec<(Address, f64)> = workers.iter()
            .filter(|(_, w)| w.assigned_shard.is_some())
            .map(|(&addr, w)| (addr, w.avg_throughput()))
            .collect();

        if throughputs.len() < 3 {
            return vec![]; // Need at least 3 workers to detect stragglers
        }

        throughputs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        let median_throughput = throughputs[throughputs.len() / 2].1;

        if median_throughput <= 0.0 {
            return vec![];
        }

        throughputs.iter()
            .filter(|(_, t)| *t < median_throughput * 0.5)
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Rebalance a straggler: halve its shard and give the other half to a fast worker.
    pub fn rebalance_straggler(&mut self, straggler: &Address, fast_worker: &Address) -> bool {
        let straggler_idx = self.shards.iter().position(|s| s.assigned_to.as_ref() == Some(straggler));

        if let Some(idx) = straggler_idx {
            if self.shards[idx].size() <= 1 {
                return false; // Can't split further
            }
            let new_id = self.next_shard_id;
            self.next_shard_id += 1;
            let mut new_shard = self.shards[idx].split(new_id);
            new_shard.assigned_to = Some(*fast_worker);
            self.shards.push(new_shard);
            return true;
        }
        false
    }

    /// Get summary statistics.
    pub fn summary(&self) -> PartitionSummary {
        PartitionSummary {
            total_population: self.total_population,
            num_shards: self.shards.len(),
            num_orphaned: self.shards.iter().filter(|s| s.orphaned).count(),
            generation: self.generation,
            best_fitness: self.shards.iter().map(|s| s.best_fitness).fold(0.0f64, f64::max),
            migration_buffer_size: self.migration_buffer.len(),
        }
    }
}

/// Summary of the current partitioning state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionSummary {
    pub total_population: usize,
    pub num_shards: usize,
    pub num_orphaned: usize,
    pub generation: u64,
    pub best_fitness: f64,
    pub migration_buffer_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_state::{WorkerCapabilities, WorkerState, ResourceAllocation};

    fn make_worker(addr_byte: u8, gpu_count: u32) -> (Address, WorkerState) {
        let addr = Address::from([addr_byte; 20]);
        let caps = WorkerCapabilities {
            cpu_cores: 8,
            gpu_count,
            gpu_memory_mib: 16384,
            ram_mib: 32768,
            benchmark_score: None,
        };
        (addr, WorkerState::new(addr, caps, ResourceAllocation::full()))
    }

    #[test]
    fn test_partition_equal_workers() {
        let mut partitioner = WorkPartitioner::new(10_000);
        let mut workers = HashMap::new();
        for i in 1..=4u8 {
            let (addr, state) = make_worker(i, 1);
            workers.insert(addr, state);
        }
        partitioner.partition_for_workers(&workers);

        assert_eq!(partitioner.shards.len(), 4);
        let total: usize = partitioner.shards.iter().map(|s| s.size()).sum();
        assert_eq!(total, 10_000);
        // Each shard should be roughly 2500
        for shard in &partitioner.shards {
            assert!(shard.size() >= 2400 && shard.size() <= 2600);
        }
    }

    #[test]
    fn test_partition_weighted_workers() {
        let mut partitioner = WorkPartitioner::new(10_000);
        let mut workers = HashMap::new();
        let (addr1, state1) = make_worker(1, 0); // CPU only
        let (addr2, state2) = make_worker(2, 4); // 4 GPUs
        workers.insert(addr1, state1);
        workers.insert(addr2, state2);
        partitioner.partition_for_workers(&workers);

        assert_eq!(partitioner.shards.len(), 2);
        let total: usize = partitioner.shards.iter().map(|s| s.size()).sum();
        assert_eq!(total, 10_000);
        // GPU worker should have a much larger shard
        let gpu_shard = partitioner.shards.iter().find(|s| s.assigned_to == Some(Address::from([2; 20]))).unwrap();
        let cpu_shard = partitioner.shards.iter().find(|s| s.assigned_to == Some(Address::from([1; 20]))).unwrap();
        assert!(gpu_shard.size() > cpu_shard.size() * 2);
    }

    #[test]
    fn test_add_worker_splits_largest() {
        let mut partitioner = WorkPartitioner::new(10_000);
        let mut workers = HashMap::new();
        let (addr1, state1) = make_worker(1, 1);
        workers.insert(addr1, state1);
        partitioner.partition_for_workers(&workers);
        assert_eq!(partitioner.shards.len(), 1);
        assert_eq!(partitioner.shards[0].size(), 10_000);

        // Add a second worker — should split
        let addr2 = Address::from([2; 20]);
        partitioner.add_worker(addr2);
        assert_eq!(partitioner.shards.len(), 2);
        let total: usize = partitioner.shards.iter().map(|s| s.size()).sum();
        assert_eq!(total, 10_000);
    }

    #[test]
    fn test_remove_worker_redistributes() {
        let mut partitioner = WorkPartitioner::new(10_000);
        let mut workers = HashMap::new();
        for i in 1..=3u8 {
            let (addr, state) = make_worker(i, 1);
            workers.insert(addr, state);
        }
        partitioner.partition_for_workers(&workers);
        assert_eq!(partitioner.shards.len(), 3);

        // Remove worker 2
        let addr2 = Address::from([2; 20]);
        partitioner.remove_worker(&addr2);

        // Should be down to 2 shards, total still 10k
        assert_eq!(partitioner.shards.len(), 2);
        let total: usize = partitioner.shards.iter().map(|s| s.size()).sum();
        assert_eq!(total, 10_000);
    }

    #[test]
    fn test_generation_advance() {
        let mut partitioner = WorkPartitioner::new(1000);
        let mut workers = HashMap::new();
        let (addr, state) = make_worker(1, 1);
        workers.insert(addr, state);
        partitioner.partition_for_workers(&workers);

        assert_eq!(partitioner.generation, 0);
        partitioner.advance_generation();
        assert_eq!(partitioner.generation, 1);
        assert!(partitioner.migration_buffer.is_empty());
    }
}
