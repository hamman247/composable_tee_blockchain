# Security Analysis

## 1. Root Trust Bootstrapping and Child TEE Key Isolation

### Trust Model
The Root Trust TEE is a software-based root of trust that generates the ML-DSA root keypair at initialization. **No hardware-based root of trust is used** — no Intel SGX EPID, AMD SEV-SNP, AWS Nitro, or equivalent.

### Initialization Process
1. Root Trust TEE generates a fresh ML-DSA-65 (Dilithium3) root keypair
2. The root private key is sealed using ML-KEM-768 (Kyber) key encapsulation
3. Root Trust's own sealed file includes the dk (it is self-sovereign — no higher authority)
4. The root public key is embedded in the genesis configuration and stored on-chain in `AttestationAnchor.sol`
5. Every full node can verify any TEE's certificate against this public key

### Child TEE Key Isolation
When the Root Trust TEE certifies a new child TEE, the process ensures the creator/operator **cannot access, use, or reverse-engineer** the child's private key:

1. **Key generation**: The child TEE's ML-DSA keypair is generated **inside the Root Trust enclave**
2. **Sealing**: The keypair is sealed (encrypted under a Kyber KEM shared secret). The sealed blob — which does NOT contain the KEM decapsulation key (dk) — is written to disk
3. **Vault storage**: The dk is stored only in Root Trust's **in-memory vault** (`dk_vault`). It is never written to the filesystem
4. **Disk contents**: The sealed blob on disk contains: KEM ciphertext + encrypted signing key + public key + integrity hash. Without the dk, the encrypted signing key is computationally infeasible to recover (Kyber768 security level)
5. **Provisioning**: The child TEE obtains its dk via a PQC-encrypted ephemeral channel (see Section 3)

### What the creator/operator CAN see on disk
- Sealed blobs: encrypted, useless without the dk
- Certificates: only public keys and code hashes (public information)
- Root Trust's own sealed file (Root Trust is self-sovereign)
- Genesis configuration (public keys only)

### What the creator/operator CANNOT see
- Any child TEE's private (signing) key
- Any child TEE's KEM decapsulation key
- The content of provisioning channel messages (encrypted with child's ephemeral key)

### Security Properties
- **Key isolation**: Child private keys exist only inside enclaves (Root Trust during certification, child TEE after provisioning)
- **Non-extractability**: The sealed blob is an opaque encrypted object — the dk never touches disk for child TEEs
- **Forward secrecy**: Each provisioning uses a fresh ephemeral Kyber keypair, so compromising one session doesn't compromise others
- **Auditability**: The root public key is immutable after genesis and verifiable by every node
- **Single point of trust**: The Root Trust TEE is the sole trust anchor; its in-memory vault holds all dk's

### Mitigations
- Root Trust TEE runs on a dedicated, isolated machine
- Key rotation: new Root Trust TEE can be certified by governance vote
- Multi-party ceremony for genesis Root Trust initialization
- Restarting Root Trust requires re-certifying all child TEEs (dk's are in-memory only)

## 2. Remote Attestation Chaining

### Chain of Trust
```
Root Trust TEE (root ML-DSA public key in genesis)
    └── signs → RootTrustCertificate for TEE-1
        └── contains: TEE-1 code hash, TEE-1 public key
    └── signs → RootTrustCertificate for TEE-2
        └── contains: TEE-2 code hash, TEE-2 public key
```

### Verification Steps (per block)
1. Extract `SignedRoundComplete` from block extra-data
2. Look up TEE's public key in local registry (synced from `TEERegistry.sol`)
3. Verify ML-DSA signature over the round-complete message
4. Deserialize `AttestationEvidence` from the signed message
5. Verify Root Trust certificate signature using the genesis root public key
6. Verify TEE's self-signature over the evidence
7. Compare `enclave_measurement` against on-chain `codeHash`
8. Check certificate hasn't expired
9. Verify nonce for freshness

### Simulator vs. Production
- **Simulator**: attestation evidence is structurally valid but contains `PlatformData::Simulator` — accepted only when `--tee-mode=simulator`
- **Production**: requires real hardware attestation quotes — the node rejects simulator attestations in production mode

## 3. Post-Quantum Key Sealing & Secure Provisioning

### Algorithms Used
| Purpose | Algorithm | NIST Standard |
|---------|-----------|---------------|
| Signatures | Dilithium3 (ML-DSA-65) | FIPS 204 |
| Key Encapsulation | Kyber768 (ML-KEM-768) | FIPS 203 |
| Key Derivation | SHA3-256 in counter mode | FIPS 202 |

### Key Sealing Process (inside Root Trust)
1. Generate Kyber768 KEM keypair `(pk, sk)`
2. Encapsulate against `pk` → shared secret `ss` + ciphertext `ct`
3. Derive encryption key: `SHA3-256(ss || "tee-chain-key-sealing-v1")`
4. XOR-encrypt the ML-DSA signing key with the derived key stream (SHA3 in counter mode)
5. **Write to disk** (sealed blob): `ct` + encrypted signing key + public key + integrity hash
6. **Keep in memory** (dk vault): `sk` (the KEM decapsulation key)
7. Integrity hash: `SHA3-256(signing_key || public_key)` for tamper detection after unsealing

### Secure Provisioning Channel
When a child TEE needs its signing key, it contacts Root Trust via a PQC-encrypted channel:

```
Child TEE                           Root Trust
    |                                   |
    |-- Generate ephemeral Kyber KP ----|
    |   (eph_pk, eph_sk)                |
    |                                   |
    |-- ProvisioningRequest(eph_pk) --->|
    |                                   |
    |   Encapsulate(eph_pk) → ss, ct    |
    |   Encrypt(dk, ss) → encrypted_dk  |
    |                                   |
    |<-- ProvisioningResponse(ct, enc) -|
    |                                   |
    |   Decapsulate(ct, eph_sk) → ss    |
    |   Decrypt(encrypted_dk, ss) → dk  |
    |   Unseal(blob, dk) → keypair      |
    |   Destroy eph_sk and dk           |
    |                                   |
```

### Security of the Provisioning Channel
- **Interception resistance**: The creator/operator can observe `ProvisioningRequest` and `ProvisioningResponse` on the wire, but cannot derive the shared secret without `eph_sk` (which only exists in the child TEE's memory)
- **Test-proven**: `test_intercepted_provisioning_response_fails` verifies that an attacker with a different ephemeral key cannot decrypt the response
- **Ephemeral keys**: Each provisioning session uses a fresh Kyber keypair — no session keys are reused
- **Domain separation**: Provisioning uses domain `"tee-chain-provisioning-v1"`, separate from sealing's `"tee-chain-key-sealing-v1"`
- **Integrity verification**: The dk has a SHA3-256 integrity hash to detect corruption or tampering

### Quantum Resistance
- All TEE-to-TEE communication uses ML-KEM for key exchange
- All signatures (certificates, round-complete messages, attestation) use ML-DSA
- **No classical cryptography** (RSA, ECDSA, DH) is used in any TEE path

## 4. Replay Protection

### Round ID Monotonicity
- Each TEE maintains a monotonically increasing `round_id`
- The consensus engine tracks `last_round_ids` per TEE
- Any block with `round_id <= last_known_round_id` is rejected
- This prevents replaying old valid blocks

### Parent Hash Binding
- Every `RoundCompleteMessage` includes `parent_block_hash`
- The consensus engine verifies this matches the actual parent
- This binds each round-complete to a specific chain position

### Timestamp Enforcement
- Attestation evidence includes a timestamp and nonce
- Nodes can reject evidence that is too old (configurable staleness window)

### Nonce
- Each `AttestationEvidence` contains a random 32-byte nonce
- Prevents evidence replay across different verification requests

## 5. Sybil Resistance

### TEE Registration
- Anyone can register a TEE binary on-chain via `TEERegistry.sol`
- **Registering does NOT grant mining rights** — user TEEs start as non-mining
- Mining eligibility requires a successful DAO governance proposal
- This prevents unauthorized block production even if someone deploys a TEE

### DAO Gatekeeping
- Promoting a TEE to mining-eligible requires:
  - 1,000 TEEC collateral
  - 7-day voting period
  - Simple majority
  - 10% quorum of total staked tokens
- This creates a significant economic and social barrier to Sybil attacks

### Code Hash Verification
- Every registered TEE stores its code hash on-chain
- The attestation evidence's `enclave_measurement` must match
- This prevents registering one TEE binary but running a different one

## 6. Compromised TEE Handling

### Emergency Freeze
- Any staker holding ≥2% of total staked tokens can trigger an immediate freeze
- The frozen TEE's blocks are rejected by all nodes
- An automatic revocation proposal is created for normal governance review
- Freeze requires 5,000 TEEC collateral (returned if revocation passes)

### Revocation
- Full mining rights revocation via DAO proposal
- Sets `miningEligible = false` on-chain
- All nodes sync this state and reject future blocks from the TEE

### Detection Mechanisms
- Nodes can detect anomalous behavior: invalid signatures, mismatched code hashes, timestamp violations
- Community monitoring via the open registry and attestation evidence
- On-chain events for all TEE state changes (registered, frozen, unfrozen, deregistered)

### Recovery
1. Emergency freeze halts the compromised TEE immediately
2. DAO proposal confirms or reverses the freeze
3. If confirmed, TEE is permanently deregistered
4. New TEE can be registered with patched code and a new code hash
5. Root Trust TEE certifies the replacement TEE
