// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./StakingToken.sol";
import "./TEERegistry.sol";

/// @title Treasury - DAO treasury that holds funds and executes governance decisions
contract Treasury {
    address public governance;

    event Executed(address indexed target, uint256 value, bytes data, bool success);
    event Received(address indexed from, uint256 amount);

    modifier onlyGovernance() {
        require(msg.sender == governance, "Only governance");
        _;
    }

    constructor(address _governance) {
        governance = _governance;
    }

    /// @notice Execute an arbitrary call (only via DAO governance)
    function execute(address target, uint256 value, bytes calldata data) external onlyGovernance returns (bool, bytes memory) {
        (bool success, bytes memory result) = target.call{value: value}(data);
        emit Executed(target, value, data, success);
        return (success, result);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }
}

/// @title DAOGovernance - Stake-weighted governance for TEE-chain
///
/// ## Proposal Types and Collateral
///
/// | Type             | Collateral  | Quorum | Purpose                                |
/// |------------------|-------------|--------|----------------------------------------|
/// | PromoteTEE       | 1,000 TEEC  | 10%    | Grant mining eligibility to a TEE      |
/// | RevokeMining     | 1,000 TEEC  | 10%    | Revoke mining eligibility              |
/// | TreasurySpend    | 1,000 TEEC  | 10%    | Spend from DAO treasury                |
/// | EmergencyFreeze  | 5,000 TEEC  | 2%     | Immediately freeze mining + auto-vote  |
///
/// ## Emergency Freeze Flow
///
/// 1. Anyone with ≥2% of staked tokens + 5,000 TEEC collateral calls `emergencyFreeze(teeId)`
/// 2. The TEE's mining rights are IMMEDIATELY frozen (it can still operate, just can't mine)
/// 3. A revocation vote (RevokeMining) is automatically created with normal 10% quorum
/// 4. After 7 days:
///    - If the vote PASSES (quorum met + majority for): TEE is permanently revoked,
///      proposer gets 100% of collateral back
///    - If the vote FAILS: freeze is lifted, TEE can mine again,
///      50% of collateral is burned, 50% goes to DAO treasury
contract DAOGovernance {
    StakingToken public stakingToken;
    TEERegistry public teeRegistry;
    Treasury public treasury;

    uint256 public constant VOTING_PERIOD = 7 days;
    uint256 public constant QUORUM_BPS = 1000;           // 10% for normal votes
    uint256 public constant EMERGENCY_QUORUM_BPS = 200;   // 2% for initiating freeze
    uint256 public constant PROPOSAL_COLLATERAL = 1000 ether;
    uint256 public constant EMERGENCY_COLLATERAL = 5000 ether;

    /// @dev Dead address used for burning tokens
    address public constant BURN_ADDRESS = address(0xdead);

    enum ProposalType { PromoteTEE, RevokeMining, EmergencyFreeze, TreasurySpend }
    enum ProposalStatus { Active, Passed, Failed, Executed }

    struct Proposal {
        uint256 id;
        ProposalType pType;
        address proposer;
        bytes32 targetTeeId;
        bytes callData;
        uint256 collateral;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 deadline;
        ProposalStatus status;
        uint256 maxRewardPerBlock;
        bool miningEligible;
        /// @dev If true, this proposal was auto-created by an emergency freeze.
        ///      Failure lifts the freeze and penalizes collateral.
        bool isEmergencyRevocation;
        /// @dev The max reward the TEE had before the freeze (to restore on failure).
        uint256 preFreezeMaxReward;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    event ProposalCreated(uint256 indexed id, ProposalType pType, address proposer, bytes32 targetTeeId);
    event Voted(uint256 indexed id, address voter, bool support, uint256 weight);
    event ProposalExecuted(uint256 indexed id, ProposalStatus status);
    event EmergencyFreezeTriggered(bytes32 indexed teeId, address triggeredBy, uint256 revocationProposalId);
    event CollateralReturned(uint256 indexed proposalId, address proposer, uint256 amount);
    event CollateralSlashed(uint256 indexed proposalId, uint256 burned, uint256 toTreasury);
    event FreezeLiftedAfterFailedVote(bytes32 indexed teeId);

    constructor(address _token, address _registry, address _treasury) {
        stakingToken = StakingToken(_token);
        teeRegistry = TEERegistry(_registry);
        treasury = Treasury(payable(_treasury));
    }

    /// @notice Create a governance proposal
    /// @dev Cannot create EmergencyFreeze via propose() — use emergencyFreeze() instead
    function propose(
        ProposalType pType,
        bytes32 targetTeeId,
        bytes calldata callData,
        bool miningEligible,
        uint256 maxRewardPerBlock
    ) external returns (uint256) {
        require(pType != ProposalType.EmergencyFreeze, "Use emergencyFreeze()");

        uint256 collateral = PROPOSAL_COLLATERAL;
        require(stakingToken.balanceOf(msg.sender) >= collateral, "Insufficient collateral");
        stakingToken.transferFrom(msg.sender, address(this), collateral);

        proposalCount++;
        Proposal storage p = proposals[proposalCount];
        p.id = proposalCount;
        p.pType = pType;
        p.proposer = msg.sender;
        p.targetTeeId = targetTeeId;
        p.callData = callData;
        p.collateral = collateral;
        p.deadline = block.timestamp + VOTING_PERIOD;
        p.status = ProposalStatus.Active;
        p.maxRewardPerBlock = maxRewardPerBlock;
        p.miningEligible = miningEligible;
        p.isEmergencyRevocation = false;

        emit ProposalCreated(proposalCount, pType, msg.sender, targetTeeId);
        return proposalCount;
    }

    /// @notice Vote on a proposal (voting power = staked tokens)
    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(p.status == ProposalStatus.Active, "Not active");
        require(block.timestamp < p.deadline, "Voting ended");
        require(!hasVoted[proposalId][msg.sender], "Already voted");

        uint256 weight = stakingToken.stakedOf(msg.sender);
        require(weight > 0, "No voting power");

        hasVoted[proposalId][msg.sender] = true;
        if (support) {
            p.votesFor += weight;
        } else {
            p.votesAgainst += weight;
        }
        emit Voted(proposalId, msg.sender, support, weight);
    }

    /// @notice Execute a proposal after voting period ends
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.status == ProposalStatus.Active, "Not active");
        require(block.timestamp >= p.deadline, "Voting not ended");

        uint256 totalVotes = p.votesFor + p.votesAgainst;
        uint256 quorum = (stakingToken.totalStaked() * QUORUM_BPS) / 10000;
        bool quorumMet = totalVotes >= quorum;
        bool majority = p.votesFor > p.votesAgainst;

        if (quorumMet && majority) {
            p.status = ProposalStatus.Passed;
            _executeProposal(p);
            // Return 100% of collateral to proposer
            stakingToken.transfer(p.proposer, p.collateral);
            emit CollateralReturned(proposalId, p.proposer, p.collateral);
        } else {
            p.status = ProposalStatus.Failed;

            // If this was an emergency revocation that failed, lift the freeze
            if (p.isEmergencyRevocation) {
                teeRegistry.unfreezeTEE(p.targetTeeId);
                // Restore mining eligibility with pre-freeze reward cap
                teeRegistry.setMiningEligible(p.targetTeeId, true, p.preFreezeMaxReward);
                emit FreezeLiftedAfterFailedVote(p.targetTeeId);
            }

            // Slash collateral: 50% burned, 50% to treasury
            uint256 burnAmount = p.collateral / 2;
            uint256 treasuryAmount = p.collateral - burnAmount;
            stakingToken.transfer(BURN_ADDRESS, burnAmount);
            stakingToken.transfer(address(treasury), treasuryAmount);
            emit CollateralSlashed(proposalId, burnAmount, treasuryAmount);
        }
        emit ProposalExecuted(proposalId, p.status);
    }

    /// @notice Emergency freeze a TEE's mining rights
    ///
    /// Requires:
    /// - Caller has ≥2% of total staked tokens
    /// - Caller has 5,000 TEEC collateral
    ///
    /// Effects:
    /// - TEE's mining is IMMEDIATELY frozen (TEE itself continues operating)
    /// - A RevokeMining proposal is auto-created with normal 10% quorum
    /// - If the revocation vote passes: TEE stays revoked, full collateral returned
    /// - If it fails: freeze is lifted, 50% collateral burned, 50% to treasury
    function emergencyFreeze(bytes32 teeId) external {
        uint256 weight = stakingToken.stakedOf(msg.sender);
        uint256 threshold = (stakingToken.totalStaked() * EMERGENCY_QUORUM_BPS) / 10000;
        require(weight >= threshold, "Insufficient stake for emergency freeze");
        require(stakingToken.balanceOf(msg.sender) >= EMERGENCY_COLLATERAL, "Insufficient collateral");

        // Capture the TEE's current max reward before freezing
        (, , , , , , , , , uint256 currentMaxReward, bool wasMining, ) = teeRegistry.tees(teeId);
        require(wasMining, "TEE not currently mining");

        stakingToken.transferFrom(msg.sender, address(this), EMERGENCY_COLLATERAL);

        // Immediately freeze the TEE's mining rights (TEE keeps operating)
        teeRegistry.freezeTEE(teeId);

        // Auto-create a revocation proposal with NORMAL 10% quorum
        proposalCount++;
        Proposal storage p = proposals[proposalCount];
        p.id = proposalCount;
        p.pType = ProposalType.RevokeMining;
        p.proposer = msg.sender;
        p.targetTeeId = teeId;
        p.collateral = EMERGENCY_COLLATERAL;
        p.deadline = block.timestamp + VOTING_PERIOD;
        p.status = ProposalStatus.Active;
        p.isEmergencyRevocation = true;
        p.preFreezeMaxReward = currentMaxReward;

        emit EmergencyFreezeTriggered(teeId, msg.sender, proposalCount);
        emit ProposalCreated(proposalCount, ProposalType.RevokeMining, msg.sender, teeId);
    }

    function _executeProposal(Proposal storage p) internal {
        if (p.pType == ProposalType.PromoteTEE) {
            teeRegistry.setMiningEligible(p.targetTeeId, p.miningEligible, p.maxRewardPerBlock);
        } else if (p.pType == ProposalType.RevokeMining) {
            // For emergency revocations that passed, the TEE is already frozen.
            // Deregister or leave frozen depending on the intent.
            // We permanently revoke mining and leave it frozen.
            // If it was already frozen by emergency, this is a no-op on freeze.
            if (!p.isEmergencyRevocation) {
                // Normal revocation — just disable mining
                teeRegistry.setMiningEligible(p.targetTeeId, false, 0);
            }
            // Emergency revocation that passed — TEE stays frozen, mining stays off.
            // Nothing else to do; the freeze already disabled mining.
        } else if (p.pType == ProposalType.TreasurySpend) {
            (address target, uint256 value) = abi.decode(p.callData, (address, uint256));
            treasury.execute(target, value, "");
        }
    }

    function getProposal(uint256 id) external view returns (
        ProposalType pType, address proposer, bytes32 targetTeeId,
        uint256 votesFor, uint256 votesAgainst, uint256 deadline,
        ProposalStatus status, bool isEmergencyRevocation
    ) {
        Proposal storage p = proposals[id];
        return (p.pType, p.proposer, p.targetTeeId, p.votesFor, p.votesAgainst,
                p.deadline, p.status, p.isEmergencyRevocation);
    }
}
