//! Local TEE registry maintained by each node.
//!
//! Mirrors on-chain TEERegistry.sol state and tracks TEE instance online status.

use std::collections::HashMap;
use tee_types::{TeeId, TeeRegistration, TeeInstanceStatus, TeeRole, TeeStatus};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("TEE not found: {0}")]
    NotFound(TeeId),
    #[error("TEE is frozen: {0}")]
    Frozen(TeeId),
    #[error("TEE is not mining eligible: {0}")]
    NotMiningEligible(TeeId),
    #[error("Root Trust TEE cannot mine: {0}")]
    RootTrustCannotMine(TeeId),
}

/// Node-local registry of TEE registrations synced from on-chain state.
#[derive(Debug, Clone)]
pub struct TeeRegistry {
    /// All registered TEEs indexed by TEE ID.
    registrations: HashMap<TeeId, TeeRegistration>,
    /// Online instance status.
    instance_status: HashMap<TeeId, Vec<TeeInstanceStatus>>,
    /// Round-robin queue for TEE-1 block production.
    round_robin_queue: Vec<TeeId>,
    /// Current position in the round-robin queue.
    round_robin_index: usize,
}

impl TeeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            registrations: HashMap::new(),
            instance_status: HashMap::new(),
            round_robin_queue: Vec::new(),
            round_robin_index: 0,
        }
    }

    /// Register a TEE (from genesis or on-chain event).
    pub fn register(&mut self, registration: TeeRegistration) {
        let tee_id = registration.tee_id;
        tracing::info!(%tee_id, role = ?registration.role, "Registered TEE");
        
        // Add to round-robin queue if it's a block coordinator
        if registration.role == TeeRole::BlockCoordinator
            && registration.config.mining_eligible
            && registration.status == TeeStatus::Active
        {
            self.round_robin_queue.push(tee_id);
        }
        
        self.registrations.insert(tee_id, registration);
    }

    /// Get a TEE registration by ID.
    pub fn get(&self, tee_id: &TeeId) -> Option<&TeeRegistration> {
        self.registrations.get(tee_id)
    }

    /// Check if a TEE is allowed to produce blocks.
    pub fn can_produce_block(&self, tee_id: &TeeId) -> Result<bool, RegistryError> {
        let reg = self.registrations.get(tee_id)
            .ok_or(RegistryError::NotFound(*tee_id))?;

        if reg.role == TeeRole::RootTrust {
            return Err(RegistryError::RootTrustCannotMine(*tee_id));
        }

        if reg.status == TeeStatus::Frozen {
            return Err(RegistryError::Frozen(*tee_id));
        }

        if !reg.config.mining_eligible {
            return Err(RegistryError::NotMiningEligible(*tee_id));
        }

        Ok(true)
    }

    /// Get the public key for a registered TEE.
    pub fn get_public_key(&self, tee_id: &TeeId) -> Option<&[u8]> {
        self.registrations.get(tee_id)
            .map(|r| r.pqc_public_key.as_slice())
    }

    /// Advance the round-robin queue and return the next block producer.
    pub fn next_block_producer(&mut self) -> Option<TeeId> {
        if self.round_robin_queue.is_empty() {
            return None;
        }
        let tee_id = self.round_robin_queue[self.round_robin_index];
        self.round_robin_index = (self.round_robin_index + 1) % self.round_robin_queue.len();
        Some(tee_id)
    }

    /// Peek at the next block producer without advancing the queue.
    pub fn peek_next_block_producer(&self) -> Option<TeeId> {
        if self.round_robin_queue.is_empty() {
            return None;
        }
        Some(self.round_robin_queue[self.round_robin_index])
    }

    /// Freeze a TEE (from DAO emergency action).
    pub fn freeze(&mut self, tee_id: &TeeId) -> Result<(), RegistryError> {
        let reg = self.registrations.get_mut(tee_id)
            .ok_or(RegistryError::NotFound(*tee_id))?;
        reg.status = TeeStatus::Frozen;
        self.round_robin_queue.retain(|id| id != tee_id);
        tracing::warn!(%tee_id, "TEE frozen");
        Ok(())
    }

    /// Unfreeze a TEE.
    pub fn unfreeze(&mut self, tee_id: &TeeId) -> Result<(), RegistryError> {
        let reg = self.registrations.get_mut(tee_id)
            .ok_or(RegistryError::NotFound(*tee_id))?;
        reg.status = TeeStatus::Active;
        if reg.config.mining_eligible && reg.role == TeeRole::BlockCoordinator {
            self.round_robin_queue.push(*tee_id);
        }
        tracing::info!(%tee_id, "TEE unfrozen");
        Ok(())
    }

    /// Get all registered TEE IDs.
    pub fn all_tee_ids(&self) -> Vec<TeeId> {
        self.registrations.keys().copied().collect()
    }

    /// Get number of registered TEEs.
    pub fn count(&self) -> usize {
        self.registrations.len()
    }
}

impl Default for TeeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
