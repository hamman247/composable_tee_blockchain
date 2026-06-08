//! Genesis state initialization.

use anyhow::Result;
use tee_types::GenesisConfig;

/// Load genesis configuration from a JSON file.
pub fn load_genesis(path: &str) -> Result<GenesisConfig> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read genesis file at {path}: {e}"))?;
    
    let genesis: GenesisConfig = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("Failed to parse genesis JSON: {e}"))?;
    
    // Validate genesis
    validate_genesis(&genesis)?;
    
    Ok(genesis)
}

/// Validate genesis configuration.
fn validate_genesis(genesis: &GenesisConfig) -> Result<()> {
    // Must have at least Root Trust TEE
    let has_root_trust = genesis.genesis_tees.iter()
        .any(|t| t.role == tee_types::TeeRole::RootTrust);
    
    if !has_root_trust {
        anyhow::bail!("Genesis must include a Root Trust TEE");
    }

    // Must have at least one mining TEE
    let has_mining_tee = genesis.genesis_tees.iter()
        .any(|t| t.role != tee_types::TeeRole::RootTrust);
    
    if !has_mining_tee {
        anyhow::bail!("Genesis must include at least one mining TEE");
    }

    // Root Trust TEE must not be mining eligible
    for tee in &genesis.genesis_tees {
        if tee.role == tee_types::TeeRole::RootTrust && tee.config.mining_eligible {
            anyhow::bail!("Root Trust TEE must not be mining eligible");
        }
    }

    // Chain ID must be non-zero
    if genesis.chain_id == 0 {
        anyhow::bail!("Chain ID must be non-zero");
    }

    Ok(())
}

/// Generate a default genesis configuration for simulator mode.
pub fn generate_default_genesis() -> Result<GenesisConfig> {
    use alloy_primitives::{Address, U256};
    use tee_crypto::PqcSigningKeypair;
    use tee_types::*;
    use sha3::{Sha3_256, Digest};

    // Generate Root Trust keypair
    let root_trust_kp = PqcSigningKeypair::generate()
        .map_err(|e| anyhow::anyhow!("Failed to generate Root Trust keypair: {e}"))?;

    // Generate TEE-1 (Block Coordinator) keypair
    let tee1_kp = PqcSigningKeypair::generate()
        .map_err(|e| anyhow::anyhow!("Failed to generate TEE-1 keypair: {e}"))?;

    // Generate TEE-2 (AI Training) keypair
    let tee2_kp = PqcSigningKeypair::generate()
        .map_err(|e| anyhow::anyhow!("Failed to generate TEE-2 keypair: {e}"))?;

    let root_trust_id = TeeId::new({
        let mut hasher = Sha3_256::new();
        hasher.update(b"root-trust-tee-v1");
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    let tee1_id = TeeId::new({
        let mut hasher = Sha3_256::new();
        hasher.update(b"tee1-block-coordinator-v1");
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    let tee2_id = TeeId::new({
        let mut hasher = Sha3_256::new();
        hasher.update(b"tee2-ai-training-v1");
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    });

    let operator_addr = Address::from([0x01; 20]);
    let treasury_addr = Address::from([0x02; 20]);

    let genesis = GenesisConfig {
        chain_id: 0x7EE1,
        timestamp: chrono::Utc::now().timestamp() as u64,
        gas_limit: 30_000_000,
        genesis_tees: vec![
            GenesisTee {
                tee_id: root_trust_id,
                role: TeeRole::RootTrust,
                code_hash: [0xAA; 32],
                public_key: root_trust_kp.public_key_bytes().to_vec(),
                certificate: None, // Root Trust is self-certified
                operator: operator_addr,
                config: TeeConfig {
                    name: "Root Trust TEE".to_string(),
                    description: "Generates and certifies the root-of-trust for all TEEs".to_string(),
                    api_endpoints: vec!["grpc://localhost:50051".to_string()],
                    max_reward_per_block: U256::ZERO,
                    mining_eligible: false,
                    custom_params: vec![],
                },
            },
            GenesisTee {
                tee_id: tee1_id,
                role: TeeRole::BlockCoordinator,
                code_hash: [0xBB; 32],
                public_key: tee1_kp.public_key_bytes().to_vec(),
                certificate: None, // Will be set during initialization
                operator: operator_addr,
                config: TeeConfig {
                    name: "TEE-1: RPC & Block Production Coordinator".to_string(),
                    description: "Runs EVM JSON-RPC, coordinates block production via round-robin".to_string(),
                    api_endpoints: vec!["http://localhost:8545".to_string()],
                    max_reward_per_block: U256::ZERO, // No block rewards, only tx fees
                    mining_eligible: true,
                    custom_params: vec![],
                },
            },
            GenesisTee {
                tee_id: tee2_id,
                role: TeeRole::AiTraining,
                code_hash: [0xCC; 32],
                public_key: tee2_kp.public_key_bytes().to_vec(),
                certificate: None,
                operator: operator_addr,
                config: TeeConfig {
                    name: "TEE-2: Distributed AI Training & Inference".to_string(),
                    description: "Genetic algorithm training with proportional reward distribution".to_string(),
                    api_endpoints: vec!["http://localhost:8546".to_string()],
                    max_reward_per_block: U256::from(100_000_000_000_000_000_000u128), // 100 tokens
                    mining_eligible: true,
                    custom_params: vec![],
                },
            },
        ],
        allocations: vec![
            GenesisAllocation {
                address: operator_addr,
                balance: U256::from(1_000_000_000_000_000_000_000_000u128), // 1M tokens
                staked: U256::from(100_000_000_000_000_000_000_000u128),    // 100K staked
            },
            GenesisAllocation {
                address: treasury_addr,
                balance: U256::from(500_000_000_000_000_000_000_000u128),   // 500K tokens
                staked: U256::ZERO,
            },
        ],
        root_trust_public_key: root_trust_kp.public_key_bytes().to_vec(),
        dao_treasury_balance: U256::from(500_000_000_000_000_000_000_000u128),
        total_supply: U256::from(10_000_000_000_000_000_000_000_000u128), // 10M tokens
    };

    Ok(genesis)
}
