//! TEE-Chain Node
//!
//! A custom EVM-compatible blockchain node that uses TEE-verified work
//! instead of traditional Proof-of-Work for block production.
//!
//! ## Architecture
//! - Custom consensus engine validates blocks via TEE signatures
//! - Attestation verification chains back to Root Trust TEE
//! - All cryptography uses post-quantum algorithms (ML-DSA, ML-KEM)
//! - JSON-RPC server exposes standard Ethereum + custom TEE APIs

mod genesis;
mod rpc;
mod state;

use anyhow::Result;
use tee_types::{NodeConfig, TeeMode};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting TEE-Chain Node v{}", env!("CARGO_PKG_VERSION"));

    // Parse configuration
    let config = parse_config()?;
    tracing::info!(
        chain_id = config.chain_id,
        tee_mode = ?config.tee_mode,
        rpc_addr = %config.rpc_addr,
        "Node configuration loaded"
    );

    // Load genesis and initialize state
    let genesis = genesis::load_genesis(&config.genesis_path)?;
    tracing::info!(
        num_genesis_tees = genesis.genesis_tees.len(),
        "Genesis configuration loaded"
    );

    // Initialize the node state
    let node_state = state::NodeState::from_genesis(&genesis, &config)?;
    tracing::info!(
        registered_tees = node_state.consensus_engine().consensus.registry().count(),
        "Node state initialized from genesis"
    );

    // Start the JSON-RPC server
    let rpc_handle = rpc::start_rpc_server(
        &config.rpc_addr,
        node_state.clone(),
    ).await?;
    tracing::info!(addr = %config.rpc_addr, "JSON-RPC server started");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down TEE-Chain Node");

    Ok(())
}

fn parse_config() -> Result<NodeConfig> {
    let args: Vec<String> = std::env::args().collect();
    
    let mut config = NodeConfig::default();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--chain-id" => {
                i += 1;
                config.chain_id = args[i].parse()?;
            }
            "--tee-mode" => {
                i += 1;
                config.tee_mode = match args[i].as_str() {
                    "simulator" => TeeMode::Simulator,
                    "production" => TeeMode::Production,
                    other => anyhow::bail!("Unknown TEE mode: {other}"),
                };
            }
            "--rpc-addr" => {
                i += 1;
                config.rpc_addr = args[i].clone();
            }
            "--p2p-addr" => {
                i += 1;
                config.p2p_addr = args[i].clone();
            }
            "--data-dir" => {
                i += 1;
                config.data_dir = args[i].clone();
            }
            "--genesis" => {
                i += 1;
                config.genesis_path = args[i].clone();
            }
            "--root-trust-key" => {
                i += 1;
                config.root_trust_public_key = args[i].clone();
            }
            "--help" => {
                println!("TEE-Chain Node");
                println!();
                println!("USAGE:");
                println!("    tee-node [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    --chain-id <ID>           Chain ID (default: 0xTEE1)");
                println!("    --tee-mode <MODE>         TEE mode: simulator|production (default: simulator)");
                println!("    --rpc-addr <ADDR>         JSON-RPC listen address (default: 127.0.0.1:8545)");
                println!("    --p2p-addr <ADDR>         P2P listen address (default: 0.0.0.0:30303)");
                println!("    --data-dir <PATH>         Data directory (default: ./data)");
                println!("    --genesis <PATH>          Genesis config file (default: ./genesis.json)");
                println!("    --root-trust-key <HEX>    Root Trust TEE public key (hex)");
                std::process::exit(0);
            }
            other => {
                anyhow::bail!("Unknown argument: {other}. Use --help for usage.");
            }
        }
        i += 1;
    }
    
    Ok(config)
}
