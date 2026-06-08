# TEE-Chain: TEE-Verified EVM Blockchain

A fully EVM-compatible blockchain where mining equals successfully running a registered TEE workload and producing a cryptographically verifiable post-quantum signature.

## Architecture

- **Consensus**: TEE-signed round-complete messages replace hash-based PoW
- **Root of Trust**: Software-based Root Trust TEE (no hardware RoT dependency)
- **Cryptography**: Post-quantum throughout (ML-DSA/Dilithium for signatures, ML-KEM/Kyber for encryption)
- **EVM**: Standard transaction format, JSON-RPC, Solidity support
- **Governance**: On-chain stake-weighted DAO

## Project Structure

```
tee-chain/
├── crates/                          # Rust workspace
│   ├── tee-types/                   # Shared types
│   ├── tee-crypto/                  # PQC primitives (Dilithium3, Kyber768)
│   ├── tee-attestation/             # Attestation verification
│   ├── tee-consensus/               # TEE consensus engine
│   └── tee-node/                    # Main node binary
├── contracts/                       # Solidity (Foundry)
│   ├── src/
│   │   ├── StakingToken.sol         # ERC-20 with staking
│   │   ├── AttestationAnchor.sol    # Root Trust public key store
│   │   ├── TEERegistry.sol          # TEE registration
│   │   ├── DAOGovernance.sol        # Governance + Treasury
│   │   ├── JobMarketplace.sol       # User TEE job payments
│   │   └── BlockRewards.sol         # Reward distribution
│   └── test/TEEChain.t.sol          # 21 tests
├── tee-templates/                   # TEE implementations
│   ├── root-trust/                  # Root Trust TEE (certifier)
│   ├── tee1-block-coordinator/      # Block production (round-robin)
│   └── tee2-ai-training/            # AI training/inference
└── deploy/                          # Docker + scripts
```

## Quick Start

### Prerequisites
- Rust 1.79+
- Foundry (forge, cast, anvil)
- Docker & Docker Compose (optional)

### Build

```bash
# Build all Rust crates
cargo build --release

# Build Solidity contracts
cd contracts && forge build

# Run all tests
cargo test
cd contracts && forge test -vv
```

### Run (Simulator Mode)

```bash
# 1. Initialize Root Trust TEE and certify genesis TEEs
cargo run --release -p root-trust-tee -- ./data

# 2. Start the node
cargo run --release -p tee-node -- \
  --tee-mode simulator \
  --genesis ./data/genesis.json \
  --rpc-addr 127.0.0.1:8545

# 3. Start TEE-1 Block Coordinator
cargo run --release -p tee1-block-coordinator -- \
  ./data/tee1-block-coordinator_sealed.json

# 4. Start TEE-2 AI Training
cargo run --release -p tee2-ai-training
```

### Docker Compose

```bash
cd deploy
docker-compose up --build
```

## Genesis TEEs

| TEE | Role | Mining | Block Rewards |
|-----|------|--------|---------------|
| Root Trust | Certifier | ❌ Never | None |
| TEE-1 | Block Coordinator | ✅ Round-robin | Tx fees only |
| TEE-2 | AI Training | ✅ Threshold | Proportional |

## DAO Governance

| Parameter | Value |
|-----------|-------|
| Voting Period | 7 days |
| Quorum | 10% of staked |
| Emergency Freeze | 2% of staked |
| Regular Collateral | 1,000 TEEC |
| Emergency Collateral | 5,000 TEEC |

## Security

See [docs/security.md](docs/security.md) for the full security analysis covering Root Trust bootstrapping, attestation chaining, PQC key sealing, replay protection, and compromised TEE handling.

## License

MIT OR Apache-2.0
