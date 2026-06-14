//! Staking verification for gating inference access.
//!
//! Users must have staked a minimum amount of TEEC tokens to use the
//! Ollama inference API. Higher stakes grant higher rate limits.
//!
//! In production, the staking state is read from the on-chain StakingToken
//! contract. In simulator mode, it uses a local in-memory map.

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum stake required to use the inference API (100 TEEC).
pub const MIN_STAKE_WEI: u128 = 100_000_000_000_000_000_000; // 100 * 1e18

/// Base rate limit (queries per epoch) for the minimum stake.
const BASE_RATE_LIMIT: u64 = 100;

/// Epoch duration in seconds (1 hour).
const EPOCH_DURATION_SECS: u64 = 3600;

/// Staking registry — tracks who has staked and how much.
#[derive(Debug, Clone)]
pub struct StakingRegistry {
    /// Address → staked amount in wei.
    stakes: HashMap<Address, U256>,
    /// Minimum stake required (in wei).
    min_stake: U256,
}

/// Error when a user fails the staking check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakingError {
    /// User has no stake at all.
    NoStake { address: Address },
    /// User's stake is below the minimum.
    InsufficientStake {
        address: Address,
        staked: U256,
        required: U256,
    },
    /// User has exceeded their rate limit for this epoch.
    RateLimitExceeded {
        address: Address,
        used: u64,
        limit: u64,
    },
}

impl std::fmt::Display for StakingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStake { address } => write!(f, "No stake found for {}", address),
            Self::InsufficientStake { address, staked, required } => {
                write!(f, "{} staked {} but {} required", address, staked, required)
            }
            Self::RateLimitExceeded { address, used, limit } => {
                write!(f, "{} used {}/{} queries this epoch", address, used, limit)
            }
        }
    }
}

/// Usage budget for a single user based on their stake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBudget {
    /// Address.
    pub address: Address,
    /// Amount staked (wei).
    pub staked: U256,
    /// Queries allowed per epoch.
    pub queries_per_epoch: u64,
    /// Tokens allowed per epoch.
    pub tokens_per_epoch: u64,
}

impl StakingRegistry {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            min_stake: U256::from(MIN_STAKE_WEI),
        }
    }

    /// Register a stake (simulator mode — in production, read from chain).
    pub fn set_stake(&mut self, address: Address, amount: U256) {
        if amount.is_zero() {
            self.stakes.remove(&address);
        } else {
            self.stakes.insert(address, amount);
        }
    }

    /// Get the stake for an address.
    pub fn get_stake(&self, address: &Address) -> U256 {
        self.stakes.get(address).copied().unwrap_or(U256::ZERO)
    }

    /// Check if an address has sufficient stake to use the API.
    pub fn check_stake(&self, address: &Address) -> Result<UsageBudget, StakingError> {
        let staked = self.get_stake(address);

        if staked.is_zero() {
            return Err(StakingError::NoStake { address: *address });
        }

        if staked < self.min_stake {
            return Err(StakingError::InsufficientStake {
                address: *address,
                staked,
                required: self.min_stake,
            });
        }

        // Rate limit scales linearly with stake:
        // 100 TEEC → 100 queries/epoch
        // 1000 TEEC → 1000 queries/epoch
        // 10000 TEEC → 10000 queries/epoch
        let stake_multiplier = staked / self.min_stake;
        let queries_per_epoch = BASE_RATE_LIMIT
            * u64::try_from(stake_multiplier).unwrap_or(u64::MAX);
        let tokens_per_epoch = queries_per_epoch * 1000; // ~1000 tokens per query avg

        Ok(UsageBudget {
            address: *address,
            staked,
            queries_per_epoch,
            tokens_per_epoch,
        })
    }

    /// Number of stakers.
    pub fn staker_count(&self) -> usize {
        self.stakes.len()
    }

    /// Total staked across all users.
    pub fn total_staked(&self) -> U256 {
        self.stakes.values().copied().fold(U256::ZERO, |acc, v| acc + v)
    }
}

/// Rate limiter that tracks per-epoch usage.
#[derive(Debug)]
pub struct RateLimiter {
    /// Address → queries used in current epoch.
    usage: HashMap<Address, u64>,
    /// Current epoch start timestamp.
    epoch_start: u64,
    /// Epoch duration in seconds.
    epoch_duration: u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            usage: HashMap::new(),
            epoch_start: chrono::Utc::now().timestamp() as u64,
            epoch_duration: EPOCH_DURATION_SECS,
        }
    }

    /// Check rate limit and record a query.
    pub fn check_and_record(
        &mut self,
        address: &Address,
        budget: &UsageBudget,
    ) -> Result<u64, StakingError> {
        // Check for epoch rollover
        let now = chrono::Utc::now().timestamp() as u64;
        if now >= self.epoch_start + self.epoch_duration {
            self.usage.clear();
            self.epoch_start = now;
        }

        let used = self.usage.entry(*address).or_insert(0);
        if *used >= budget.queries_per_epoch {
            return Err(StakingError::RateLimitExceeded {
                address: *address,
                used: *used,
                limit: budget.queries_per_epoch,
            });
        }

        *used += 1;
        Ok(*used)
    }

    /// Get current usage for an address.
    pub fn current_usage(&self, address: &Address) -> u64 {
        self.usage.get(address).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn teec(amount: u64) -> U256 {
        U256::from(amount) * U256::from(1_000_000_000_000_000_000u128)
    }

    #[test]
    fn test_no_stake_rejected() {
        let registry = StakingRegistry::new();
        let addr = Address::from([0x01; 20]);
        let result = registry.check_stake(&addr);
        assert!(matches!(result, Err(StakingError::NoStake { .. })));
    }

    #[test]
    fn test_insufficient_stake_rejected() {
        let mut registry = StakingRegistry::new();
        let addr = Address::from([0x01; 20]);
        registry.set_stake(addr, teec(50)); // 50 TEEC < 100 minimum
        let result = registry.check_stake(&addr);
        assert!(matches!(result, Err(StakingError::InsufficientStake { .. })));
    }

    #[test]
    fn test_sufficient_stake_accepted() {
        let mut registry = StakingRegistry::new();
        let addr = Address::from([0x01; 20]);
        registry.set_stake(addr, teec(100)); // Exact minimum
        let budget = registry.check_stake(&addr).unwrap();
        assert_eq!(budget.queries_per_epoch, 100);
    }

    #[test]
    fn test_higher_stake_higher_rate_limit() {
        let mut registry = StakingRegistry::new();
        let addr = Address::from([0x01; 20]);
        registry.set_stake(addr, teec(1000)); // 10× minimum
        let budget = registry.check_stake(&addr).unwrap();
        assert_eq!(budget.queries_per_epoch, 1000); // 10× base
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();
        let addr = Address::from([0x01; 20]);
        let budget = UsageBudget {
            address: addr,
            staked: teec(100),
            queries_per_epoch: 3,
            tokens_per_epoch: 3000,
        };

        assert!(limiter.check_and_record(&addr, &budget).is_ok()); // 1/3
        assert!(limiter.check_and_record(&addr, &budget).is_ok()); // 2/3
        assert!(limiter.check_and_record(&addr, &budget).is_ok()); // 3/3
        let result = limiter.check_and_record(&addr, &budget);      // 4/3 → fail
        assert!(matches!(result, Err(StakingError::RateLimitExceeded { .. })));
    }

    #[test]
    fn test_total_staked() {
        let mut registry = StakingRegistry::new();
        registry.set_stake(Address::from([0x01; 20]), teec(100));
        registry.set_stake(Address::from([0x02; 20]), teec(500));
        assert_eq!(registry.total_staked(), teec(600));
    }

    #[test]
    fn test_remove_stake() {
        let mut registry = StakingRegistry::new();
        let addr = Address::from([0x01; 20]);
        registry.set_stake(addr, teec(100));
        assert_eq!(registry.staker_count(), 1);
        registry.set_stake(addr, U256::ZERO);
        assert_eq!(registry.staker_count(), 0);
    }
}
