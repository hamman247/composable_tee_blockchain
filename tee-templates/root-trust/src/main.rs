//! Root Trust TEE - Software-based root of trust for TEE-chain.
//!
//! ## Security Model
//!
//! The Root Trust TEE initializes child TEEs such that:
//! 1. Child TEE private keys are generated INSIDE the Root Trust enclave
//! 2. The sealed blob written to disk does NOT contain the decapsulation key
//! 3. The dk is kept in Root Trust's in-memory vault, never touching disk in cleartext
//! 4. Child TEEs obtain their dk via a PQC-encrypted provisioning channel
//! 5. The creator/operator CANNOT access, use, or reverse-engineer child TEE keys
//!
//! ### What the creator CAN see (on disk):
//! - Sealed blobs: encrypted signing keys + KEM ciphertext (useless without dk)
//! - Certificates: TEE public keys signed by Root Trust (public information)
//! - Root Trust's own sealed file (Root Trust is self-sovereign)
//!
//! ### What the creator CANNOT see:
//! - Any child TEE private (signing) key
//! - Any child TEE decapsulation key
//! - The provisioning channel content (encrypted with child's ephemeral key)

use tee_crypto::{
    PqcSigningKeypair, sign_message,
    seal_keypair, unseal_keypair,
    save_sealed_blob, load_sealed_blob,
    save_sealed_keys_self, load_sealed_keys_self,
    create_provisioning_response,
    ProvisioningSecret, ProvisioningRequest, ProvisioningResponse, SealedKeyMaterial,
};
use tee_types::{TeeId, RootTrustCertificate};
use sha3::{Sha3_256, Digest};
use alloy_primitives::B256;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;

/// The Root Trust TEE instance.
///
/// Holds an in-memory vault of provisioning secrets (dk's) for all certified TEEs.
/// These NEVER touch the filesystem. Child TEEs must request them via
/// the provisioning channel while Root Trust is running.
pub struct RootTrustTee {
    /// The root ML-DSA signing keypair.
    keypair: PqcSigningKeypair,
    /// In-memory vault: TeeId → ProvisioningSecret.
    /// These dk's are the ONLY way to unseal child TEE keys.
    /// They exist ONLY in Root Trust's enclave memory.
    dk_vault: HashMap<TeeId, VaultEntry>,
    /// Counter for issued certificates.
    cert_counter: u64,
    /// Data directory (for sealed blobs and certificates).
    data_dir: String,
}

/// An entry in the dk vault — held exclusively in Root Trust memory.
/// NOT cloneable — the dk is a unique, non-duplicable secret.
struct VaultEntry {
    /// The provisioning secret (KEM decapsulation key).
    /// Zeroized on drop — if VaultEntry is removed, the dk is scrubbed from memory.
    secret: ProvisioningSecret,
    /// The certificate for this TEE.
    certificate: RootTrustCertificate,
    /// The sealed blob path (so we know where the child TEE will read from).
    sealed_blob_path: String,
}

/// Public output from certifying a new TEE.
/// NOTE: contains ONLY public information and the opaque sealed blob path.
/// The creator CANNOT recover the private key from this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertifiedTeeOutput {
    /// Path to the sealed blob on disk (encrypted, dk NOT included).
    pub sealed_blob_path: String,
    /// The certificate signed by Root Trust (contains public key, code hash).
    pub certificate: RootTrustCertificate,
    /// The TEE's ML-DSA public key (not secret).
    pub tee_public_key: Vec<u8>,
    /// The TEE ID.
    pub tee_id: TeeId,
}

impl RootTrustTee {
    /// Initialize a new Root Trust TEE, generating fresh root keys.
    /// Root Trust's OWN key is the only key where we store dk on disk
    /// (it's self-sovereign — there is no higher authority to provision it).
    pub fn initialize(data_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let sealed_path = format!("{}/root_trust_sealed.json", data_dir);

        let keypair = if Path::new(&sealed_path).exists() {
            println!("[RootTrust] Loading existing root keys from {}", sealed_path);
            let (sealed, secret) = load_sealed_keys_self(&sealed_path)?;
            unseal_keypair(&sealed, &secret)?
        } else {
            println!("[RootTrust] Generating new ML-DSA root keypair...");
            let kp = PqcSigningKeypair::generate()?;
            let (sealed, secret) = seal_keypair(&kp)?;
            std::fs::create_dir_all(data_dir)?;
            save_sealed_keys_self(&sealed, &secret, &sealed_path)?;
            println!("[RootTrust] Root keys sealed to {}", sealed_path);
            println!("[RootTrust] WARNING: Root Trust sealed file includes dk (self-sovereign).");
            kp
        };

        println!("[RootTrust] Public key length: {} bytes", keypair.public_key_bytes().len());
        println!("[RootTrust] Public key hash: {}", hex::encode(&Sha3_256::digest(keypair.public_key_bytes())));

        Ok(Self {
            keypair,
            dk_vault: HashMap::new(),
            cert_counter: 0,
            data_dir: data_dir.to_string(),
        })
    }

    /// Get the root public key (for embedding in genesis/AttestationAnchor).
    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key_bytes()
    }

    /// Certify a new TEE.
    ///
    /// 1. Generates child TEE keypair INSIDE this enclave
    /// 2. Seals it — dk stays in memory, sealed blob goes to disk
    /// 3. Signs a certificate binding the TEE's public key to its code hash
    /// 4. Returns only public information + sealed blob path
    ///
    /// The creator CANNOT extract the child TEE's private key because:
    /// - The sealed blob on disk does not contain the dk
    /// - The dk is held only in `self.dk_vault` (in-memory)
    /// - The child TEE obtains the dk via `handle_provisioning_request()`
    pub fn certify_tee(
        &mut self,
        code_binary: &[u8],
        tee_name: &str,
    ) -> Result<CertifiedTeeOutput, Box<dyn std::error::Error>> {
        // ── Step 1: Generate child TEE's ML-DSA keypair inside enclave ──
        let tee_keypair = PqcSigningKeypair::generate()?;

        // ── Step 2: Compute code hash and TEE ID ──
        let code_hash = B256::from_slice(&Sha3_256::digest(code_binary));
        let tee_id = TeeId::new({
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&Sha3_256::digest(tee_name.as_bytes()));
            arr
        });

        // ── Step 3: Seal the keypair ──
        // `seal_keypair` returns (sealed_blob, provisioning_secret)
        // sealed_blob → disk (safe, opaque without dk)
        // provisioning_secret → dk_vault (in-memory only)
        let (sealed, secret) = seal_keypair(&tee_keypair)?;

        let sealed_path = format!(
            "{}/{}_sealed.json",
            self.data_dir,
            tee_name.replace(' ', "_").to_lowercase()
        );
        save_sealed_blob(&sealed, &sealed_path)?;

        // ── Step 4: Create and sign the certificate ──
        let now = chrono::Utc::now().timestamp() as u64;
        let mut cert = RootTrustCertificate {
            version: 1,
            subject_tee_id: tee_id,
            subject_code_hash: code_hash,
            subject_public_key: tee_keypair.public_key_bytes().to_vec(),
            issued_at: now,
            expires_at: 0,
            root_trust_signature: vec![],
        };
        let cert_bytes = cert.to_signing_bytes();
        cert.root_trust_signature = sign_message(&self.keypair, &cert_bytes)?;

        // ── Step 5: Store dk in vault (MEMORY ONLY — never on disk) ──
        self.dk_vault.insert(tee_id, VaultEntry {
            secret,
            certificate: cert.clone(),
            sealed_blob_path: sealed_path.clone(),
        });

        self.cert_counter += 1;
        println!(
            "[RootTrust] Certified TEE '{}' (ID: {}, cert #{})",
            tee_name, tee_id, self.cert_counter
        );
        println!(
            "[RootTrust] Sealed blob → {} (dk NOT included — held in vault)",
            sealed_path
        );

        // ── Return only public info ──
        Ok(CertifiedTeeOutput {
            sealed_blob_path: sealed_path,
            certificate: cert,
            tee_public_key: tee_keypair.public_key_bytes().to_vec(),
            tee_id,
        })
    }

    /// Handle a provisioning request from a child TEE.
    ///
    /// The child TEE sends an ephemeral KEM public key.
    /// Root Trust encrypts the dk under this ephemeral key and returns it.
    /// The creator/operator CANNOT decrypt the response because they don't
    /// hold the child TEE's ephemeral secret key (it exists only in the child's memory).
    ///
    /// ## Security properties
    /// - The dk is encrypted with a fresh shared secret derived from the child's ephemeral key
    /// - Even if the creator intercepts the ProvisioningResponse, they cannot derive the shared secret
    /// - The ephemeral key is generated inside the child TEE and never exported
    pub fn handle_provisioning_request(
        &self,
        tee_id: &TeeId,
        request: &ProvisioningRequest,
    ) -> Result<ProvisioningResponse, Box<dyn std::error::Error>> {
        let entry = self.dk_vault.get(tee_id)
            .ok_or_else(|| format!("TEE {} not found in vault", tee_id))?;

        let response = create_provisioning_response(&entry.secret, request)?;
        println!("[RootTrust] Provisioned dk for TEE {} via encrypted channel", tee_id);
        Ok(response)
    }

    /// Get the number of TEEs with dk's held in the vault.
    pub fn vault_size(&self) -> usize {
        self.dk_vault.len()
    }

    /// Check if a TEE's dk is available for provisioning.
    pub fn has_tee_in_vault(&self, tee_id: &TeeId) -> bool {
        self.dk_vault.contains_key(tee_id)
    }

    /// Export the root trust public key as hex string.
    pub fn export_public_key_hex(&self) -> String {
        hex::encode(self.keypair.public_key_bytes())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TEE-Chain Root Trust TEE (Simulator Mode) ===");
    println!("=== SECURITY: Child TEE dk's held in-memory only ===\n");

    let data_dir = std::env::args().nth(1).unwrap_or_else(|| "./root_trust_data".to_string());

    // Initialize Root Trust
    let mut root_trust = RootTrustTee::initialize(&data_dir)?;
    println!("\n[RootTrust] Root public key (hex): {}\n", root_trust.export_public_key_hex());

    // Certify genesis TEEs — keys generated internally, dk's stay in vault
    let tee1 = root_trust.certify_tee(
        b"tee1-block-coordinator-binary-v1",
        "tee1-block-coordinator",
    )?;
    println!("[RootTrust] TEE-1 certified: {}", tee1.tee_id);

    let tee2 = root_trust.certify_tee(
        b"tee2-ai-training-binary-v1",
        "tee2-ai-training",
    )?;
    println!("[RootTrust] TEE-2 certified: {}", tee2.tee_id);

    println!(
        "\n[RootTrust] Vault holds {} dk's (in-memory only, NOT on disk)",
        root_trust.vault_size()
    );

    // ── Simulate provisioning for TEE-1 ──
    println!("\n--- Simulating provisioning for TEE-1 ---");
    {
        // Child TEE generates ephemeral keypair (inside its own enclave)
        let (request, ephemeral) = tee_crypto::create_provisioning_request()?;
        println!("[TEE-1] Created provisioning request (ephemeral PK generated in-enclave)");

        // Root Trust handles the request (encrypts dk under ephemeral key)
        let response = root_trust.handle_provisioning_request(&tee1.tee_id, &request)?;
        println!("[RootTrust] Sent provisioning response (dk encrypted for TEE-1 only)");

        // Child TEE receives response and extracts dk
        let recovered_secret = tee_crypto::receive_provisioning_response(&response, &ephemeral)?;
        println!("[TEE-1] Received dk via encrypted channel");

        // Child TEE loads sealed blob from disk and unseals with the dk
        let sealed = tee_crypto::load_sealed_blob(&tee1.sealed_blob_path)?;
        let keypair = tee_crypto::unseal_keypair(&sealed, &recovered_secret)?;
        println!("[TEE-1] Unsealed signing keypair ({} byte public key)", keypair.public_key_bytes().len());

        // Verify it matches the certificate
        assert_eq!(keypair.public_key_bytes(), &tee1.tee_public_key[..]);
        println!("[TEE-1] ✓ Public key matches certificate");
    }

    // ── Simulate provisioning for TEE-2 ──
    println!("\n--- Simulating provisioning for TEE-2 ---");
    {
        let (request, ephemeral) = tee_crypto::create_provisioning_request()?;
        let response = root_trust.handle_provisioning_request(&tee2.tee_id, &request)?;
        let recovered_secret = tee_crypto::receive_provisioning_response(&response, &ephemeral)?;
        let sealed = tee_crypto::load_sealed_blob(&tee2.sealed_blob_path)?;
        let keypair = tee_crypto::unseal_keypair(&sealed, &recovered_secret)?;
        assert_eq!(keypair.public_key_bytes(), &tee2.tee_public_key[..]);
        println!("[TEE-2] ✓ Provisioned and verified");
    }

    // ── Export genesis info (public information only) ──
    let genesis_info = serde_json::json!({
        "root_trust_public_key": root_trust.export_public_key_hex(),
        "tee1": {
            "tee_id": hex::encode(tee1.tee_id.0.as_slice()),
            "public_key": hex::encode(&tee1.tee_public_key),
            "sealed_blob_path": tee1.sealed_blob_path,
            "certificate": serde_json::to_string(&tee1.certificate)?,
        },
        "tee2": {
            "tee_id": hex::encode(tee2.tee_id.0.as_slice()),
            "public_key": hex::encode(&tee2.tee_public_key),
            "sealed_blob_path": tee2.sealed_blob_path,
            "certificate": serde_json::to_string(&tee2.certificate)?,
        },
        "security_note": "Sealed blobs on disk do NOT contain decapsulation keys. \
            Child TEEs must contact Root Trust for provisioning.",
    });

    let genesis_path = format!("{}/genesis_tee_info.json", data_dir);
    std::fs::write(&genesis_path, serde_json::to_string_pretty(&genesis_info)?)?;
    println!("\n[RootTrust] Genesis TEE info exported to {}", genesis_path);
    println!("[RootTrust] Root Trust TEE initialized and ready.");
    println!("[RootTrust] NOTE: dk's are held in-memory. Restarting Root Trust requires re-certification.");

    Ok(())
}
