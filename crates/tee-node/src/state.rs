//! Node state management.

use std::sync::{Arc, RwLock};
use anyhow::Result;
use alloy_primitives::{Address, B256, U256};
use tee_consensus::{TeeConsensusEngine, TeeRegistry};
use tee_types::*;

#[derive(Clone)]
pub struct NodeState {
    inner: Arc<RwLock<NodeStateInner>>,
}

pub struct NodeStateInner {
    pub consensus: TeeConsensusEngine,
    pub block_number: u64,
    pub block_hash: B256,
    pub pending_txns: Vec<PendingTransaction>,
    pub chain_id: u64,
    pub balances: std::collections::HashMap<Address, U256>,
    pub nonces: std::collections::HashMap<Address, u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingTransaction {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: U256,
    pub timestamp: u64,
}

impl NodeState {
    pub fn from_genesis(genesis: &GenesisConfig, config: &NodeConfig) -> Result<Self> {
        let mut registry = TeeRegistry::new();
        for gt in &genesis.genesis_tees {
            registry.register(TeeRegistration {
                tee_id: gt.tee_id,
                code_hash: B256::from(gt.code_hash),
                pqc_public_key: gt.public_key.clone(),
                root_trust_certificate: gt.certificate.clone().unwrap_or_default(),
                role: gt.role,
                status: TeeStatus::Active,
                operator: gt.operator,
                config: gt.config.clone(),
                registered_at_block: 0,
            });
        }

        let root_pk = if config.root_trust_public_key.is_empty() {
            genesis.root_trust_public_key.clone()
        } else {
            hex::decode(&config.root_trust_public_key)?
        };

        let consensus = TeeConsensusEngine::new(root_pk, registry, config.tee_mode);
        let mut balances = std::collections::HashMap::new();
        for alloc in &genesis.allocations {
            balances.insert(alloc.address, alloc.balance);
        }

        Ok(Self {
            inner: Arc::new(RwLock::new(NodeStateInner {
                consensus, block_number: 0, block_hash: B256::ZERO,
                pending_txns: Vec::new(), chain_id: genesis.chain_id,
                balances, nonces: std::collections::HashMap::new(),
            })),
        })
    }

    pub fn block_number(&self) -> u64 { self.inner.read().unwrap_or_else(|e| e.into_inner()).block_number }
    pub fn block_hash(&self) -> B256 { self.inner.read().unwrap_or_else(|e| e.into_inner()).block_hash }
    pub fn chain_id(&self) -> u64 { self.inner.read().unwrap_or_else(|e| e.into_inner()).chain_id }

    pub fn get_balance(&self, addr: &Address) -> U256 {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).balances.get(addr).copied().unwrap_or(U256::ZERO)
    }
    pub fn get_nonce(&self, addr: &Address) -> u64 {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).nonces.get(addr).copied().unwrap_or(0)
    }
    pub fn pending_txn_count(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).pending_txns.len()
    }
    pub fn add_pending_txn(&self, txn: PendingTransaction) -> Result<B256> {
        let hash = txn.hash;
        self.inner.write().unwrap_or_else(|e| e.into_inner()).pending_txns.push(txn);
        Ok(hash)
    }

    pub fn consensus_engine(&self) -> std::sync::RwLockReadGuard<'_, NodeStateInner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn process_block(&self, src: &SignedRoundComplete) -> Result<u64> {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.block_number += 1;
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(&inner.block_number.to_le_bytes());
        h.update(inner.block_hash.as_slice());
        inner.block_hash = B256::from_slice(&h.finalize());
        for p in &src.message.payments {
            *inner.balances.entry(p.recipient).or_insert(U256::ZERO) += p.amount;
        }
        for inc in &src.message.incentives {
            *inner.balances.entry(inc.recipient).or_insert(U256::ZERO) += inc.amount;
        }
        let hashes: std::collections::HashSet<_> = src.message.transaction_hashes.iter().collect();
        inner.pending_txns.retain(|t| !hashes.contains(&t.hash));
        tracing::info!(block = inner.block_number, hash = %inner.block_hash, "Block processed");
        Ok(inner.block_number)
    }
}
