//! Node and chain configuration types.

use serde::{Deserialize, Serialize};

/// TEE execution mode for the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeMode {
    /// Accept only production attestations with real hardware evidence.
    Production,
    /// Accept simulator attestations for development/testing.
    Simulator,
}

/// Configuration for the TEE-chain node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// TEE mode (simulator or production).
    pub tee_mode: TeeMode,
    /// Chain ID for EVM transactions.
    pub chain_id: u64,
    /// JSON-RPC listen address.
    pub rpc_addr: String,
    /// P2P listen address.
    pub p2p_addr: String,
    /// Data directory for node storage.
    pub data_dir: String,
    /// Path to genesis configuration file.
    pub genesis_path: String,
    /// Root Trust TEE public key (hex-encoded ML-DSA public key).
    pub root_trust_public_key: String,
    /// Minimum block interval in seconds.
    pub min_block_interval: u64,
    /// Minimum pending transactions to trigger block production.
    pub min_pending_txns: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            tee_mode: TeeMode::Simulator,
            chain_id: 0x7EE1,
            rpc_addr: "127.0.0.1:8545".to_string(),
            p2p_addr: "0.0.0.0:30303".to_string(),
            data_dir: "./data".to_string(),
            genesis_path: "./genesis.json".to_string(),
            root_trust_public_key: String::new(),
            min_block_interval: 30,
            min_pending_txns: 10,
        }
    }
}

/// Chain parameters stored in the genesis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainParams {
    /// Chain ID.
    pub chain_id: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Minimum block interval in seconds.
    pub min_block_interval: u64,
    /// Minimum pending transactions to trigger block production.
    pub min_pending_txns: usize,
    /// DAO governance parameters.
    pub dao_params: DaoParams,
}

/// DAO governance parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoParams {
    /// Voting period in seconds (7 days = 604800).
    pub voting_period: u64,
    /// Quorum in basis points (1000 = 10%).
    pub quorum_bps: u64,
    /// Emergency freeze quorum in basis points (200 = 2%).
    pub emergency_quorum_bps: u64,
    /// Regular proposal collateral.
    pub proposal_collateral: u64,
    /// Emergency freeze collateral.
    pub emergency_collateral: u64,
}

impl Default for DaoParams {
    fn default() -> Self {
        Self {
            voting_period: 604800,          // 7 days
            quorum_bps: 1000,               // 10%
            emergency_quorum_bps: 200,      // 2%
            proposal_collateral: 1000,
            emergency_collateral: 5000,
        }
    }
}
