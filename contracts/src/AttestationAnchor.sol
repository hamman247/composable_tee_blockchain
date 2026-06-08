// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title AttestationAnchor - Stores Root Trust TEE public key for on-chain verification
contract AttestationAnchor {
    /// @notice Root Trust TEE ML-DSA public key (immutable after genesis)
    bytes public rootTrustPublicKey;
    bool public initialized;

    event RootTrustKeySet(bytes publicKey);
    event AttestationVerified(bytes32 indexed teeId, bytes32 codeHash);

    /// @notice Set the Root Trust public key (one-time, at genesis)
    function initialize(bytes calldata _publicKey) external {
        require(!initialized, "Already initialized");
        require(_publicKey.length > 0, "Empty key");
        rootTrustPublicKey = _publicKey;
        initialized = true;
        emit RootTrustKeySet(_publicKey);
    }

    /// @notice Verify attestation evidence (delegates to PQC precompile at 0x0100)
    /// @dev In the full implementation, this calls the custom precompile for ML-DSA verification
    function verifyAttestation(
        bytes calldata evidence,
        bytes32 expectedCodeHash
    ) external view returns (bool) {
        require(initialized, "Not initialized");
        // Precompile call for PQC signature verification
        // Input: [public_key_len(32) | public_key | message_len(32) | message | signature]
        // Output: [0x01] if valid, [0x00] if invalid
        address precompile = address(0x0100);
        (bool success, bytes memory result) = precompile.staticcall(evidence);
        if (!success || result.length == 0) return false;
        return result[0] == 0x01;
    }

    /// @notice Get the root trust public key hash for quick comparisons
    function rootTrustKeyHash() external view returns (bytes32) {
        return keccak256(rootTrustPublicKey);
    }
}
