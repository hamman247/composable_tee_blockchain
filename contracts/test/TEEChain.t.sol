// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/StakingToken.sol";
import "../src/TEERegistry.sol";
import "../src/DAOGovernance.sol";
import "../src/JobMarketplace.sol";
import "../src/BlockRewards.sol";
import "../src/AttestationAnchor.sol";

contract StakingTokenTest is Test {
    StakingToken token;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        token = new StakingToken(1_000_000 ether);
        token.transfer(alice, 100_000 ether);
    }

    function test_InitialSupply() public view {
        assertEq(token.totalSupply(), 1_000_000 ether);
    }

    function test_Transfer() public {
        vm.prank(alice);
        token.transfer(bob, 1000 ether);
        assertEq(token.balanceOf(bob), 1000 ether);
        assertEq(token.balanceOf(alice), 99_000 ether);
    }

    function test_StakeAndUnstake() public {
        vm.startPrank(alice);
        token.stake(50_000 ether);
        assertEq(token.stakedOf(alice), 50_000 ether);
        assertEq(token.balanceOf(alice), 50_000 ether);
        assertEq(token.totalStaked(), 50_000 ether);
        assertEq(token.votingPower(alice), 50_000 ether);

        token.unstake(20_000 ether);
        assertEq(token.stakedOf(alice), 30_000 ether);
        assertEq(token.balanceOf(alice), 70_000 ether);
        vm.stopPrank();
    }

    function test_StakeInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert("Insufficient balance");
        token.stake(200_000 ether);
    }

    function test_UnstakeInsufficientStake() public {
        vm.prank(alice);
        vm.expectRevert("Insufficient staked balance");
        token.unstake(1 ether);
    }
}

contract TEERegistryTest is Test {
    TEERegistry registry;
    address gov = makeAddr("governance");
    bytes32 teeId = keccak256("tee-1");
    bytes32 codeHash = keccak256("code");

    function setUp() public {
        registry = new TEERegistry(gov);
    }

    function test_RegisterTEE() public {
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Block Coordinator", 100 ether, true
        );
        assertEq(registry.getTEECount(), 1);
        assertTrue(registry.isMiningEligible(teeId));
        assertTrue(registry.isOperational(teeId));
    }

    function test_RootTrustCannotMine() public {
        vm.expectRevert("Root Trust cannot mine");
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.RootTrust, address(this),
            "Root", "Root Trust", 0, true // mining=true should fail
        );
    }

    function test_FreezeTEE_OnlyStopsMining() public {
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Test", 100 ether, true
        );
        vm.prank(gov);
        registry.freezeTEE(teeId);

        // Mining is disabled
        assertFalse(registry.isMiningEligible(teeId));
        // But TEE is still operational (can serve inference, accept work, etc.)
        assertTrue(registry.isOperational(teeId));
        // Status is Frozen (mining frozen, not deregistered)
        assertEq(uint256(registry.getStatus(teeId)), uint256(TEERegistry.TeeStatus.Frozen));
    }

    function test_UnfreezeTEE() public {
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Test", 100 ether, true
        );
        vm.startPrank(gov);
        registry.freezeTEE(teeId);
        registry.unfreezeTEE(teeId);
        vm.stopPrank();
        // After unfreeze, status is Active again
        assertEq(uint256(registry.getStatus(teeId)), uint256(TEERegistry.TeeStatus.Active));
        // But mining is NOT auto-restored (governance must explicitly re-enable)
        assertFalse(registry.isMiningEligible(teeId));
    }

    function test_OnlyGovernanceCanFreeze() public {
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Test", 100 ether, true
        );
        vm.expectRevert("Only governance");
        registry.freezeTEE(teeId);
    }

    function test_DuplicateRegistrationFails() public {
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Test", 100 ether, true
        );
        vm.expectRevert("TEE already registered");
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Test", 100 ether, true
        );
    }

    function test_DeregisteredTEE_NotOperational() public {
        registry.registerTEE(
            teeId, codeHash, hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.BlockCoordinator, address(this),
            "TEE-1", "Test", 100 ether, true
        );
        vm.prank(gov);
        registry.deregisterTEE(teeId);
        assertFalse(registry.isOperational(teeId));
        assertFalse(registry.isMiningEligible(teeId));
    }
}

contract DAOGovernanceTest is Test {
    StakingToken token;
    TEERegistry registry;
    Treasury treasury;
    DAOGovernance dao;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");
    bytes32 teeId = keccak256("user-tee");

    function setUp() public {
        token = new StakingToken(10_000_000 ether);

        // Deploy with this test contract as temp governance
        registry = new TEERegistry(address(this));
        treasury = new Treasury(address(this));

        // Deploy DAO
        dao = new DAOGovernance(address(token), address(registry), address(treasury));

        // Transfer governance to DAO
        registry.setGovernance(address(dao));

        // Register a user TEE for testing (registerTEE is open to anyone)
        registry.registerTEE(
            teeId, keccak256("code"), hex"aabb", hex"ccdd",
            TEERegistry.TeeRole.UserJob, alice,
            "User TEE", "Test job", 50 ether, true
        );

        // Fund and stake alice (2M tokens, stakes 1M)
        token.transfer(alice, 2_000_000 ether);
        vm.startPrank(alice);
        token.approve(address(dao), type(uint256).max);
        token.stake(1_000_000 ether);
        vm.stopPrank();

        // Fund and stake bob (500K tokens, stakes 500K)
        token.transfer(bob, 500_000 ether);
        vm.startPrank(bob);
        token.approve(address(dao), type(uint256).max);
        token.stake(500_000 ether);
        vm.stopPrank();

        // Fund charlie (small holder)
        token.transfer(charlie, 100_000 ether);
        vm.startPrank(charlie);
        token.approve(address(dao), type(uint256).max);
        token.stake(10_000 ether);
        vm.stopPrank();
    }

    // ───────────────────────────────────────────────
    // Normal Proposal Tests
    // ───────────────────────────────────────────────

    function test_ProposeAndVote_Pass() public {
        // First revoke mining so we can promote
        bytes32 newTeeId = keccak256("new-tee");
        registry.registerTEE(
            newTeeId, keccak256("code2"), hex"eeff", hex"1122",
            TEERegistry.TeeRole.AiTraining, bob,
            "New TEE", "AI Training", 0, false
        );

        vm.prank(alice);
        uint256 pid = dao.propose(
            DAOGovernance.ProposalType.PromoteTEE,
            newTeeId, "", true, 50 ether
        );
        assertEq(pid, 1);

        vm.prank(alice);
        dao.vote(pid, true);

        vm.prank(bob);
        dao.vote(pid, true);

        // Fast forward past voting period
        vm.warp(block.timestamp + 7 days + 1);

        uint256 aliceBalBefore = token.balanceOf(alice);
        dao.execute(pid);

        // TEE should be mining eligible
        assertTrue(registry.isMiningEligible(newTeeId));
        // Alice should get 1000 TEEC collateral back
        assertEq(token.balanceOf(alice) - aliceBalBefore, 1000 ether);
    }

    function test_NormalProposal_CollateralIs1000() public {
        uint256 balBefore = token.balanceOf(alice);

        vm.prank(alice);
        dao.propose(
            DAOGovernance.ProposalType.PromoteTEE,
            teeId, "", true, 50 ether
        );

        assertEq(balBefore - token.balanceOf(alice), 1000 ether);
    }

    function test_ProposalFailsWithoutQuorum_CollateralSlashed() public {
        vm.prank(alice);
        uint256 pid = dao.propose(
            DAOGovernance.ProposalType.PromoteTEE,
            teeId, "", true, 50 ether
        );

        // No votes → quorum not met
        vm.warp(block.timestamp + 7 days + 1);

        uint256 aliceBalBefore = token.balanceOf(alice);
        uint256 treasuryBalBefore = token.balanceOf(address(treasury));
        uint256 burnBalBefore = token.balanceOf(address(0xdead));

        dao.execute(pid);

        // Alice does NOT get collateral back
        assertEq(token.balanceOf(alice), aliceBalBefore);
        // 50% (500) to treasury
        assertEq(token.balanceOf(address(treasury)) - treasuryBalBefore, 500 ether);
        // 50% (500) burned
        assertEq(token.balanceOf(address(0xdead)) - burnBalBefore, 500 ether);
    }

    function test_DoubleVoteFails() public {
        vm.prank(alice);
        uint256 pid = dao.propose(
            DAOGovernance.ProposalType.PromoteTEE,
            teeId, "", true, 50 ether
        );

        vm.prank(alice);
        dao.vote(pid, true);

        vm.prank(alice);
        vm.expectRevert("Already voted");
        dao.vote(pid, true);
    }

    function test_VoteAfterDeadlineFails() public {
        vm.prank(alice);
        uint256 pid = dao.propose(
            DAOGovernance.ProposalType.PromoteTEE,
            teeId, "", true, 50 ether
        );

        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(alice);
        vm.expectRevert("Voting ended");
        dao.vote(pid, true);
    }

    function test_CannotCreateEmergencyFreezeViaPropose() public {
        vm.prank(alice);
        vm.expectRevert("Use emergencyFreeze()");
        dao.propose(
            DAOGovernance.ProposalType.EmergencyFreeze,
            teeId, "", false, 0
        );
    }

    // ───────────────────────────────────────────────
    // Emergency Freeze Tests
    // ───────────────────────────────────────────────

    function test_EmergencyFreeze_ImmediatelyStopsMining() public {
        assertTrue(registry.isMiningEligible(teeId));

        vm.prank(alice);
        dao.emergencyFreeze(teeId);

        // Mining is immediately frozen
        assertFalse(registry.isMiningEligible(teeId));
        // But TEE is still operational
        assertTrue(registry.isOperational(teeId));
    }

    function test_EmergencyFreeze_CreatesRevocationVote() public {
        vm.prank(alice);
        dao.emergencyFreeze(teeId);

        // Should have created proposal #1
        (
            DAOGovernance.ProposalType pType,
            address proposer,
            bytes32 targetId,
            , , ,
            DAOGovernance.ProposalStatus status,
            bool isEmergencyRevocation
        ) = dao.getProposal(1);

        assertEq(uint256(pType), uint256(DAOGovernance.ProposalType.RevokeMining));
        assertEq(proposer, alice);
        assertEq(targetId, teeId);
        assertEq(uint256(status), uint256(DAOGovernance.ProposalStatus.Active));
        assertTrue(isEmergencyRevocation);
    }

    function test_EmergencyFreeze_CollateralIs5000() public {
        uint256 balBefore = token.balanceOf(alice);

        vm.prank(alice);
        dao.emergencyFreeze(teeId);

        assertEq(balBefore - token.balanceOf(alice), 5000 ether);
    }

    function test_EmergencyFreeze_RequiresMinimumStake() public {
        // Charlie only has 10K staked, total staked is 1.51M, 2% = 30,200
        vm.prank(charlie);
        vm.expectRevert("Insufficient stake for emergency freeze");
        dao.emergencyFreeze(teeId);
    }

    function test_EmergencyFreeze_RevocationPasses_CollateralReturned() public {
        uint256 aliceBalBefore = token.balanceOf(alice);

        vm.prank(alice);
        dao.emergencyFreeze(teeId);

        // Vote to confirm the revocation (10% quorum needed)
        vm.prank(alice);
        dao.vote(1, true);
        vm.prank(bob);
        dao.vote(1, true);

        vm.warp(block.timestamp + 7 days + 1);
        dao.execute(1);

        // TEE stays frozen, mining stays off
        assertFalse(registry.isMiningEligible(teeId));
        assertEq(uint256(registry.getStatus(teeId)), uint256(TEERegistry.TeeStatus.Frozen));

        // Alice gets ALL 5000 TEEC collateral back
        assertEq(token.balanceOf(alice), aliceBalBefore);
    }

    function test_EmergencyFreeze_RevocationFails_FreezeLiftedAndSlashed() public {
        uint256 aliceBalBefore = token.balanceOf(alice);

        vm.prank(alice);
        dao.emergencyFreeze(teeId);

        // Nobody votes or vote against → fails
        vm.prank(bob);
        dao.vote(1, false);

        vm.warp(block.timestamp + 7 days + 1);

        uint256 treasuryBalBefore = token.balanceOf(address(treasury));
        uint256 burnBalBefore = token.balanceOf(address(0xdead));

        dao.execute(1);

        // Freeze is lifted — TEE can mine again
        assertTrue(registry.isMiningEligible(teeId));
        assertTrue(registry.isOperational(teeId));
        assertEq(uint256(registry.getStatus(teeId)), uint256(TEERegistry.TeeStatus.Active));

        // Alice does NOT get collateral back
        assertEq(token.balanceOf(alice), aliceBalBefore - 5000 ether);
        // 50% (2500) burned, 50% (2500) to treasury
        assertEq(token.balanceOf(address(0xdead)) - burnBalBefore, 2500 ether);
        assertEq(token.balanceOf(address(treasury)) - treasuryBalBefore, 2500 ether);
    }

    function test_EmergencyFreeze_RevocationFailsNoQuorum_FrezeLifted() public {
        vm.prank(alice);
        dao.emergencyFreeze(teeId);

        // No votes at all → fails due to quorum not met
        vm.warp(block.timestamp + 7 days + 1);
        dao.execute(1);

        // Freeze lifted, TEE can mine again
        assertTrue(registry.isMiningEligible(teeId));
    }
}

contract JobMarketplaceTest is Test {
    JobMarketplace marketplace;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address operator = makeAddr("operator");

    function setUp() public {
        marketplace = new JobMarketplace();
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function test_RegisterJob() public {
        vm.prank(alice);
        bytes32 jobId = marketplace.registerJob(keccak256("code"), hex"1234");
        assertEq(marketplace.getJobCount(), 1);
    }

    function test_DepositAndWithdraw() public {
        vm.prank(alice);
        bytes32 jobId = marketplace.registerJob(keccak256("code"), hex"1234");

        vm.prank(bob);
        marketplace.deposit{value: 10 ether}(jobId, 1 days);

        // Can't withdraw before lock-up
        vm.prank(bob);
        vm.expectRevert("Lock-up not expired");
        marketplace.withdraw(jobId, 0);

        // Fast forward past lock-up
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(bob);
        marketplace.withdraw(jobId, 0);
        assertEq(bob.balance, 100 ether);
    }

    function test_ClaimPayout() public {
        vm.prank(alice);
        bytes32 jobId = marketplace.registerJob(keccak256("code"), hex"1234");

        vm.prank(bob);
        marketplace.deposit{value: 10 ether}(jobId, 1 days);

        address[] memory ops = new address[](1);
        ops[0] = operator;
        uint256[] memory amts = new uint256[](1);
        amts[0] = 5 ether;

        marketplace.claimPayout(jobId, ops, amts, hex"");
        assertEq(operator.balance, 5 ether);
    }
}

contract AttestationAnchorTest is Test {
    AttestationAnchor anchor;

    function setUp() public {
        anchor = new AttestationAnchor();
    }

    function test_Initialize() public {
        anchor.initialize(hex"aabbccdd");
        assertTrue(anchor.initialized());
        assertEq(anchor.rootTrustPublicKey(), hex"aabbccdd");
    }

    function test_DoubleInitFails() public {
        anchor.initialize(hex"aabbccdd");
        vm.expectRevert("Already initialized");
        anchor.initialize(hex"eeff0011");
    }

    function test_EmptyKeyFails() public {
        vm.expectRevert("Empty key");
        anchor.initialize(hex"");
    }
}
