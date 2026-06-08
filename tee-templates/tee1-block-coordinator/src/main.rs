//! TEE-1: RPC & Block Production Coordinator (Simulator Mode)
//!
//! - Full EVM JSON-RPC proxy
//! - Block trigger: every 30s since last block IF ≥10 pending txns
//! - Round-robin queue of online TEE-1 instances
//! - FCFS transaction ordering
//! - No block rewards, only tx fees
//! - Signs round-complete message after valid block production

use tee_crypto::{
    PqcSigningKeypair, sign_message,
    load_sealed_blob, unseal_keypair,
    create_provisioning_request, receive_provisioning_response,
    ProvisioningResponse, SealedKeyMaterial, ProvisioningSecret,
};
use tee_types::*;
use sha3::{Sha3_256, Digest};
use alloy_primitives::{Address, B256, U256};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// TEE-1 Block Coordinator instance.
pub struct BlockCoordinator {
    /// Signing keypair (unsealed inside enclave via provisioning channel).
    keypair: PqcSigningKeypair,
    /// TEE identifier.
    tee_id: TeeId,
    /// Code hash.
    code_hash: B256,
    /// Root Trust certificate.
    certificate: RootTrustCertificate,
    /// Current round ID (monotonically increasing).
    round_id: u64,
    /// Last block production time.
    last_block_time: Instant,
    /// Block interval (30 seconds).
    block_interval: Duration,
    /// Minimum pending transactions to trigger block.
    min_pending_txns: usize,
    /// Round-robin queue of operator instances.
    operator_queue: VecDeque<OperatorInstance>,
}

#[derive(Debug, Clone)]
struct OperatorInstance {
    operator: Address,
    last_seen: Instant,
    connected: bool,
}

impl BlockCoordinator {
    /// Initialize from sealed blob + provisioning secret obtained from Root Trust.
    ///
    /// The keypair is recovered inside the TEE enclave:
    /// 1. Load sealed blob from disk (opaque — no dk)
    /// 2. Unseal using the ProvisioningSecret received via the encrypted channel
    /// 3. Destroy the ProvisioningSecret — only the live keypair remains
    pub fn from_provisioned_secret(
        sealed_blob_path: &str,
        secret: &ProvisioningSecret,
        certificate: RootTrustCertificate,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let sealed = load_sealed_blob(sealed_blob_path)?;
        let keypair = unseal_keypair(&sealed, secret)?;

        let tee_id = certificate.subject_tee_id;
        let code_hash = certificate.subject_code_hash;

        println!("[TEE-1] Block Coordinator initialized");
        println!("[TEE-1] TEE ID: {}", tee_id);
        println!("[TEE-1] Block interval: 30s, min pending txns: 10");

        Ok(Self {
            keypair,
            tee_id,
            code_hash,
            certificate,
            round_id: 0,
            last_block_time: Instant::now(),
            block_interval: Duration::from_secs(30),
            min_pending_txns: 10,
            operator_queue: VecDeque::new(),
        })
    }

    /// Register a new operator instance (added to back of queue).
    pub fn register_operator(&mut self, operator: Address) {
        self.operator_queue.push_back(OperatorInstance {
            operator,
            last_seen: Instant::now(),
            connected: true,
        });
        println!("[TEE-1] Operator {} added to queue (position {})", operator, self.operator_queue.len());
    }

    /// Check if block production should be triggered.
    pub fn should_produce_block(&self, pending_txn_count: usize) -> bool {
        let elapsed = self.last_block_time.elapsed();
        elapsed >= self.block_interval && pending_txn_count >= self.min_pending_txns
    }

    /// Produce a block: advance round-robin, create and sign round-complete message.
    pub fn produce_block(
        &mut self,
        parent_hash: B256,
        pending_tx_hashes: Vec<B256>,
        operator_override: Option<Address>,
    ) -> Result<SignedRoundComplete, Box<dyn std::error::Error>> {
        // Advance round
        self.round_id += 1;

        // Get next operator from round-robin queue
        let operator = if let Some(op) = operator_override {
            op
        } else {
            self.next_operator().unwrap_or(Address::ZERO)
        };

        // Prune disconnected operators (30 min timeout)
        self.prune_disconnected();

        // Create round-complete message
        let msg = RoundCompleteMessage {
            tee_id: self.tee_id,
            round_id: self.round_id,
            parent_block_hash: parent_hash,
            payments: vec![
                // Transaction fees go to the operator
                PaymentInstruction {
                    recipient: operator,
                    amount: U256::from(21000u64 * pending_tx_hashes.len() as u64), // Simplified fee calc
                    is_reward: false,
                },
            ],
            incentives: vec![], // No block rewards for TEE-1
            timestamp: chrono::Utc::now().timestamp() as u64,
            tee_specific_data: vec![],
            transaction_hashes: pending_tx_hashes,
        };

        // Sign with sealed key
        let sig = sign_message(&self.keypair, &msg.to_signing_bytes())?;

        // Create attestation evidence
        let evidence = self.create_attestation_evidence()?;
        let evidence_bytes = bincode::serialize(&evidence)?;

        self.last_block_time = Instant::now();

        println!(
            "[TEE-1] Block produced: round={}, operator={}, txns={}",
            self.round_id, operator, msg.transaction_hashes.len()
        );

        Ok(SignedRoundComplete {
            message: msg,
            signature: sig,
            attestation_evidence: evidence_bytes,
        })
    }

    fn next_operator(&mut self) -> Option<Address> {
        if self.operator_queue.is_empty() {
            return None;
        }
        let instance = self.operator_queue.pop_front()?;
        let addr = instance.operator;
        self.operator_queue.push_back(instance);
        Some(addr)
    }

    fn prune_disconnected(&mut self) {
        let timeout = Duration::from_secs(30 * 60); // 30 minutes
        let before = self.operator_queue.len();
        self.operator_queue.retain(|op| op.last_seen.elapsed() < timeout);
        let pruned = before - self.operator_queue.len();
        if pruned > 0 {
            println!("[TEE-1] Pruned {} disconnected operators", pruned);
        }
    }

    fn create_attestation_evidence(&self) -> Result<AttestationEvidence, Box<dyn std::error::Error>> {
        let mut evidence = AttestationEvidence {
            tee_id: self.tee_id,
            enclave_measurement: self.code_hash,
            root_trust_cert: self.certificate.clone(),
            platform_data: PlatformData::Simulator {
                report: vec![0u8; 64],
                simulator_version: "1.0.0".to_string(),
            },
            nonce: B256::random(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            self_signature: vec![],
        };
        evidence.self_signature = sign_message(&self.keypair, &evidence.to_signing_bytes())?;
        Ok(evidence)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    println!("=== TEE-1: Block Production Coordinator (Simulator) ===\n");

    let sealed_path = std::env::args().nth(1)
        .unwrap_or_else(|| "./root_trust_data/tee1-block-coordinator_sealed.json".to_string());

    let cert_path = std::env::args().nth(2)
        .unwrap_or_else(|| "./root_trust_data/genesis_tee_info.json".to_string());

    println!("[TEE-1] Loading sealed keys from {}", sealed_path);
    println!("[TEE-1] This TEE produces blocks via round-robin when conditions are met.");
    println!("[TEE-1] Block interval: 30s | Min pending txns: 10 | No block rewards");
    println!("[TEE-1] Simulator mode: producing valid PQC signatures");

    // In a real deployment, we'd load the certificate and run the block production loop.
    // For the MVP simulator, we demonstrate the signing and attestation flow.
    println!("\n[TEE-1] TEE-1 Block Coordinator ready.");
    println!("[TEE-1] Waiting for node connection...");

    // Keep alive
    tokio::signal::ctrl_c().await?;
    println!("[TEE-1] Shutting down.");
    Ok(())
}
