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
│   ├── tee-types/                   # Shared types (TeeRole, TeeId, etc.)
│   ├── tee-crypto/                  # PQC primitives (Dilithium3, Kyber768)
│   ├── tee-attestation/             # Attestation verification
│   ├── tee-consensus/               # TEE consensus engine
│   └── tee-node/                    # Main node + integration test
├── contracts/                       # Solidity (Foundry)
│   ├── src/
│   │   ├── StakingToken.sol         # ERC-20 with staking
│   │   ├── AttestationAnchor.sol    # Root Trust public key store
│   │   ├── TEERegistry.sol          # TEE registration
│   │   ├── DAOGovernance.sol        # Governance + Treasury
│   │   ├── JobMarketplace.sol       # User TEE job payments
│   │   ├── BlockRewards.sol         # Reward distribution
│   │   └── LiquidStaking.sol        # ETH liquid staking (teeETH)
│   └── test/
│       ├── TEEChain.t.sol           # Core contract tests (31)
│       └── LiquidStaking.t.sol      # Liquid staking tests (23)
├── tee-templates/                   # TEE implementations
│   ├── root-trust/                  # Root Trust TEE (certifier)
│   ├── tee1-block-coordinator/      # Block production (round-robin)
│   ├── tee2-ai-training/            # Distributed AI training
│   ├── tee3-ollama-inference/       # Ollama AI inference (EVM-signed)
│   └── tee4-eth-validator/          # Ethereum mainnet validator
└── deploy/                          # Docker + scripts
```

## TEEs

### TEE-1: Block Coordinator
Manages block production using round-robin scheduling across registered operators. Collects transactions from the mempool, orders them, and produces PQC-signed blocks.

### TEE-2: AI Training
Runs distributed transformer training (Llama-3 architecture) across many nodes. Each worker contributes proportional compute and receives proportional rewards. Supports dynamic resource allocation (1-100% of node capacity).

### TEE-3: Ollama Inference
Provides AI inference via Ollama models behind EVM wallet authentication. Users sign queries with their Ethereum private key (EIP-191), and the TEE verifies signatures via secp256k1 ecrecover. Access requires staking TEEC tokens — rate limits scale with stake amount. After serving enough queries (1,000 queries or 500K tokens), the operator can mine a block.

- **Authentication**: EIP-191 personal_sign → ecrecover inside the enclave
- **Staking gate**: 100 TEEC minimum, rate limit = stake amount queries/epoch
- **Replay protection**: Nonce tracking + 5-minute timestamp window
- **Mining**: Usage-based threshold → block with usage proof

### TEE-4: Ethereum Mainnet Validator
Runs Ethereum consensus validators on behalf of depositors via a liquid staking model. Users deposit ETH into the `LiquidStaking` smart contract and receive `teeETH` receipt tokens. The TEE operator creates 32-ETH validators from the pool and performs attestation/proposal duties.

- **Liquid staking**: Deposit ETH → mint teeETH at current exchange rate
- **Validator lifecycle**: Buffer ETH until ≥32 → create validator → attest/propose
- **Reward distribution**: 5% of staking rewards → DAO treasury, 95% → backs teeETH (exchange rate increases over time)
- **Withdrawals**: Burn teeETH → receive proportional ETH (instant if buffered, queued if staked)
- **Mining**: After continuous uptime with ≥95% attestation rate, the operator can mine a block on the TEE-chain

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

# Run all tests (109 Rust + 54 Solidity = 163 total)
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

# 5. Start TEE-3 Ollama Inference
cargo run --release -p tee3-ollama-inference

# 6. Start TEE-4 ETH Validator
cargo run --release -p tee4-eth-validator

# 7. Run full integration test (all 4 TEEs)
cargo run --release --bin integration-test
```

### Docker Compose

```bash
cd deploy
docker-compose up --build
```

## Genesis TEEs

| TEE | Role | Mining Trigger | Block Rewards |
|-----|------|----------------|---------------|
| Root Trust | Certifier | ❌ Never | None |
| TEE-1 | Block Coordinator | ✅ Round-robin | Tx fees only |
| TEE-2 | AI Training | ✅ Training threshold | Proportional to compute |
| TEE-3 | Ollama Inference | ✅ Usage threshold | 50 TEEC per block |
| TEE-4 | ETH Validator | ✅ Uptime + attestation rate | 25 TEEC per block |

## Contracts

| Contract | Purpose |
|----------|---------|
| `StakingToken.sol` | ERC-20 TEEC token with staking for governance |
| `TEERegistry.sol` | On-chain TEE registration and status |
| `DAOGovernance.sol` | Proposal/voting with emergency freeze (2% quorum) |
| `LiquidStaking.sol` | ETH deposits → teeETH tokens, 5%/95% reward split |
| `JobMarketplace.sol` | User-submitted TEE job payments |
| `BlockRewards.sol` | Mining reward distribution |
| `AttestationAnchor.sol` | Root Trust public key store |

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
