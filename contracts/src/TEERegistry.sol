// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title TEERegistry - On-chain registry of all TEE instances
/// @notice Freeze only revokes mining eligibility. The TEE itself continues operating normally.
contract TEERegistry {
    enum TeeRole { RootTrust, BlockCoordinator, AiTraining, UserJob }
    enum TeeStatus { Active, Frozen, Deregistered }

    struct TeeRecord {
        bytes32 teeId;
        bytes32 codeHash;
        bytes pqcPublicKey;
        bytes rootTrustCertificate;
        TeeRole role;
        TeeStatus status;
        address operator;
        string name;
        string description;
        uint256 maxRewardPerBlock;
        bool miningEligible;
        uint256 registeredAtBlock;
    }

    mapping(bytes32 => TeeRecord) public tees;
    bytes32[] public teeIds;
    address public governance;

    event TEERegistered(bytes32 indexed teeId, TeeRole role, address operator);
    event TEEDeregistered(bytes32 indexed teeId);
    event TEEMiningFrozen(bytes32 indexed teeId);
    event TEEMiningUnfrozen(bytes32 indexed teeId);
    event MiningEligibilityChanged(bytes32 indexed teeId, bool eligible, uint256 maxReward);

    modifier onlyGovernance() {
        require(msg.sender == governance, "Only governance");
        _;
    }

    constructor(address _governance) {
        governance = _governance;
    }

    function setGovernance(address _newGovernance) external onlyGovernance {
        governance = _newGovernance;
    }

    function registerTEE(
        bytes32 teeId,
        bytes32 codeHash,
        bytes calldata pqcPublicKey,
        bytes calldata rootTrustCert,
        TeeRole role,
        address operator,
        string calldata _name,
        string calldata _description,
        uint256 maxRewardPerBlock,
        bool miningEligible
    ) external {
        require(tees[teeId].teeId == bytes32(0), "TEE already registered");
        require(role != TeeRole.RootTrust || !miningEligible, "Root Trust cannot mine");

        tees[teeId] = TeeRecord({
            teeId: teeId,
            codeHash: codeHash,
            pqcPublicKey: pqcPublicKey,
            rootTrustCertificate: rootTrustCert,
            role: role,
            status: TeeStatus.Active,
            operator: operator,
            name: _name,
            description: _description,
            maxRewardPerBlock: maxRewardPerBlock,
            miningEligible: miningEligible,
            registeredAtBlock: block.number
        });
        teeIds.push(teeId);
        emit TEERegistered(teeId, role, operator);
    }

    function deregisterTEE(bytes32 teeId) external onlyGovernance {
        require(tees[teeId].teeId != bytes32(0), "TEE not found");
        tees[teeId].status = TeeStatus.Deregistered;
        tees[teeId].miningEligible = false;
        emit TEEDeregistered(teeId);
    }

    /// @notice Freeze a TEE's mining rights ONLY. The TEE itself continues
    ///         operating normally — it can still serve inference, accept work, etc.
    ///         It simply cannot mine blocks or receive block rewards while frozen.
    function freezeTEE(bytes32 teeId) external onlyGovernance {
        TeeRecord storage t = tees[teeId];
        require(t.teeId != bytes32(0), "TEE not found");
        require(t.status != TeeStatus.Deregistered, "TEE deregistered");
        t.status = TeeStatus.Frozen;
        t.miningEligible = false;
        emit TEEMiningFrozen(teeId);
    }

    /// @notice Restore a frozen TEE's status to Active. Mining eligibility is NOT
    ///         automatically restored — governance must call setMiningEligible separately.
    function unfreezeTEE(bytes32 teeId) external onlyGovernance {
        require(tees[teeId].status == TeeStatus.Frozen, "TEE not frozen");
        tees[teeId].status = TeeStatus.Active;
        emit TEEMiningUnfrozen(teeId);
    }

    function setMiningEligible(bytes32 teeId, bool eligible, uint256 maxReward) external onlyGovernance {
        TeeRecord storage t = tees[teeId];
        require(t.teeId != bytes32(0), "TEE not found");
        require(t.role != TeeRole.RootTrust, "Root Trust cannot mine");
        require(t.status == TeeStatus.Active, "TEE not active");
        t.miningEligible = eligible;
        t.maxRewardPerBlock = maxReward;
        emit MiningEligibilityChanged(teeId, eligible, maxReward);
    }

    function isMiningEligible(bytes32 teeId) external view returns (bool) {
        TeeRecord storage t = tees[teeId];
        return t.miningEligible && t.status == TeeStatus.Active;
    }

    /// @notice Check if a TEE is operational (Active or Frozen — anything except Deregistered)
    function isOperational(bytes32 teeId) external view returns (bool) {
        TeeRecord storage t = tees[teeId];
        return t.status == TeeStatus.Active || t.status == TeeStatus.Frozen;
    }

    function getStatus(bytes32 teeId) external view returns (TeeStatus) {
        return tees[teeId].status;
    }

    function getTEECount() external view returns (uint256) {
        return teeIds.length;
    }

    function getTEEPublicKey(bytes32 teeId) external view returns (bytes memory) {
        return tees[teeId].pqcPublicKey;
    }
}
