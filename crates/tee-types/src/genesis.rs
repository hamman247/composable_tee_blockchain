//! Genesis state configuration.

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::{TeeConfig, TeeId, TeeRole};

/// Complete genesis configuration for the TEE-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain ID.
    pub chain_id: u64,
    /// Genesis timestamp.
    pub timestamp: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Pre-registered TEEs (including Root Trust, TEE-1, TEE-2).
    pub genesis_tees: Vec<GenesisTee>,
    /// Initial token allocations.
    pub allocations: Vec<GenesisAllocation>,
    /// Root Trust TEE public key (ML-DSA).
    pub root_trust_public_key: Vec<u8>,
    /// DAO treasury initial balance.
    pub dao_treasury_balance: U256,
    /// Initial total token supply.
    pub total_supply: U256,
}

/// A TEE that is pre-registered in the genesis state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisTee {
    /// TEE identifier.
    pub tee_id: TeeId,
    /// Role of this TEE.
    pub role: TeeRole,
    /// SHA3-256 hash of the TEE binary.
    pub code_hash: [u8; 32],
    /// ML-DSA public key.
    pub public_key: Vec<u8>,
    /// Root Trust certificate (for non-Root-Trust TEEs).
    pub certificate: Option<Vec<u8>>,
    /// Operator address.
    pub operator: Address,
    /// Configuration.
    pub config: TeeConfig,
}

/// Initial token allocation in genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Recipient address.
    pub address: Address,
    /// Token balance.
    pub balance: U256,
    /// Optional: pre-staked amount.
    pub staked: U256,
}

/// Well-known system contract addresses (deterministic, set at genesis).
pub mod system_contracts {
    use alloy_primitives::Address;

    /// TEE Registry contract address.
    pub const TEE_REGISTRY: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]);

    /// DAO Governance contract address.
    pub const DAO_GOVERNANCE: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x02,
    ]);

    /// Staking Token contract address.
    pub const STAKING_TOKEN: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x03,
    ]);

    /// Job Marketplace contract address.
    pub const JOB_MARKETPLACE: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x04,
    ]);

    /// Treasury contract address.
    pub const TREASURY: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x05,
    ]);

    /// Block Rewards contract address.
    pub const BLOCK_REWARDS: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x06,
    ]);

    /// Attestation Anchor contract address.
    pub const ATTESTATION_ANCHOR: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x07,
    ]);

    /// PQC Signature Verification precompile address.
    pub const PQC_VERIFY_PRECOMPILE: Address = Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
    ]);
}
