//! TEE identity and registration types.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Unique identifier for a TEE instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TeeId(pub B256);

impl TeeId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::fmt::Display for TeeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TEE:{}", hex::encode(&self.0))
    }
}

/// The type/role of a TEE in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeRole {
    /// Root Trust TEE - certifies all other TEEs, cannot mine.
    RootTrust,
    /// Block production coordinator (TEE-1).
    BlockCoordinator,
    /// AI Training and Inference (TEE-2).
    AiTraining,
    /// Ollama Inference Service (TEE-3) — signature-gated model serving.
    OllamaInference,
    /// Ethereum Mainnet Validator (TEE-4) — liquid staking via TEE.
    EthValidator,
    /// EVM Cross-Chain Bridge (TEE-5) — trustless bridge between TEE-Chain and Ethereum.
    EvmBridge,
    /// User-submitted TEE job.
    UserJob,
}

/// Status of a TEE in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeStatus {
    /// TEE is registered and active.
    Active,
    /// TEE is frozen by emergency DAO action.
    Frozen,
    /// TEE has been deregistered.
    Deregistered,
}

/// Configuration parameters for a TEE instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    /// Human-readable name.
    pub name: String,
    /// Description of what this TEE does.
    pub description: String,
    /// API endpoints this TEE exposes.
    pub api_endpoints: Vec<String>,
    /// Maximum block reward per block (0 if no block rewards).
    pub max_reward_per_block: U256,
    /// Whether this TEE is eligible for mining.
    pub mining_eligible: bool,
    /// TEE-specific configuration parameters (opaque bytes).
    pub custom_params: Vec<u8>,
}

/// On-chain registration record for a TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeRegistration {
    /// Unique TEE identifier.
    pub tee_id: TeeId,
    /// SHA3-256 hash of the TEE binary code.
    pub code_hash: B256,
    /// ML-DSA public verification key (serialized).
    pub pqc_public_key: Vec<u8>,
    /// Certificate from Root Trust TEE.
    pub root_trust_certificate: Vec<u8>,
    /// Role of this TEE.
    pub role: TeeRole,
    /// Current status.
    pub status: TeeStatus,
    /// Operator address that controls this TEE instance.
    pub operator: Address,
    /// Configuration parameters.
    pub config: TeeConfig,
    /// Block number at which this TEE was registered.
    pub registered_at_block: u64,
}

/// Information about a TEE instance's online status (maintained locally by nodes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeInstanceStatus {
    /// TEE identifier.
    pub tee_id: TeeId,
    /// Operator address.
    pub operator: Address,
    /// Whether the instance is currently reachable.
    pub online: bool,
    /// Last time this instance was seen.
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Position in the round-robin queue (for TEE-1).
    pub queue_position: Option<u64>,
}
