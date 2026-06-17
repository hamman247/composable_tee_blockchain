// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/LiquidStaking.sol";

contract LiquidStakingTest is Test {
    LiquidStaking staking;
    address treasury = makeAddr("treasury");
    address operator = makeAddr("teeOperator");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    function setUp() public {
        staking = new LiquidStaking(treasury, operator);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(carol, 100 ether);
    }

    // ═══════════════════════ Deposits ═══════════════════════

    function test_FirstDeposit_OneToOne() public {
        vm.prank(alice);
        staking.deposit{value: 10 ether}();
        assertEq(staking.balanceOf(alice), 10 ether, "First deposit should be 1:1");
        assertEq(staking.totalSupply(), 10 ether);
        assertEq(staking.totalPooledEther(), 10 ether);
        assertEq(staking.bufferedEther(), 10 ether);
    }

    function test_MultipleDeposits_SameRate() public {
        vm.prank(alice);
        staking.deposit{value: 10 ether}();
        vm.prank(bob);
        staking.deposit{value: 20 ether}();
        assertEq(staking.balanceOf(bob), 20 ether, "Same rate before rewards");
        assertEq(staking.totalPooledEther(), 30 ether);
    }

    function test_ZeroDeposit_Reverts() public {
        vm.prank(alice);
        vm.expectRevert("Zero deposit");
        staking.deposit{value: 0}();
    }

    // ═══════════════════════ Exchange Rate ═══════════════════════

    function test_ExchangeRate_InitiallyOneToOne() public view {
        assertEq(staking.exchangeRate(), 1 ether);
    }

    function test_ExchangeRate_IncreasesAfterRewards() public {
        vm.prank(alice);
        staking.deposit{value: 100 ether}();

        // Report 10 ETH rewards (5% to treasury = 0.5 ETH, 95% to pool = 9.5 ETH)
        vm.prank(operator);
        staking.reportRewards(10 ether);

        // Pool now has 109.5 ETH backing ~100 teeETH + treasury shares
        uint256 rate = staking.exchangeRate();
        assertGt(rate, 1 ether, "Rate should increase after rewards");
    }

    function test_DepositAfterRewards_ReceivesFewerShares() public {
        vm.prank(alice);
        staking.deposit{value: 100 ether}();

        vm.prank(operator);
        staking.reportRewards(10 ether);

        // Bob deposits after rewards — should get fewer teeETH per ETH
        vm.prank(bob);
        staking.deposit{value: 10 ether}();
        assertLt(staking.balanceOf(bob), 10 ether, "Should get fewer shares after rewards");
    }

    // ═══════════════════════ Validator Creation ═══════════════════════

    function test_CreateValidator_Needs32ETH() public {
        vm.prank(alice);
        staking.deposit{value: 31 ether}();
        vm.prank(operator);
        vm.expectRevert("Need 32 ETH buffered");
        staking.createValidator();
    }

    function test_CreateValidator_Success() public {
        vm.prank(alice);
        staking.deposit{value: 64 ether}();

        vm.startPrank(operator);
        staking.createValidator();
        assertEq(staking.activeValidators(), 1);
        assertEq(staking.bufferedEther(), 32 ether);

        staking.createValidator();
        assertEq(staking.activeValidators(), 2);
        assertEq(staking.bufferedEther(), 0);
        vm.stopPrank();
    }

    function test_CreateValidator_OnlyOperator() public {
        vm.prank(alice);
        staking.deposit{value: 32 ether}();
        vm.prank(alice);
        vm.expectRevert("Only TEE operator");
        staking.createValidator();
    }

    function test_BufferAccumulates_Until32() public {
        vm.prank(alice);
        staking.deposit{value: 10 ether}();
        assertEq(staking.bufferedEther(), 10 ether);
        assertEq(staking.pendingValidators(), 0);

        vm.prank(bob);
        staking.deposit{value: 25 ether}();
        assertEq(staking.bufferedEther(), 35 ether);
        assertEq(staking.pendingValidators(), 1);
    }

    // ═══════════════════════ Rewards Distribution ═══════════════════════

    function test_RewardsDistribution_5pctTreasury() public {
        vm.prank(alice);
        staking.deposit{value: 100 ether}();

        vm.prank(operator);
        staking.reportRewards(10 ether);

        assertEq(staking.totalRewardsAccrued(), 10 ether);
        assertEq(staking.totalTreasuryFees(), 0.5 ether); // 5% of 10
        // Treasury gets teeETH shares
        assertGt(staking.balanceOf(treasury), 0, "Treasury should have shares");
    }

    function test_RewardsDistribution_95pctToPool() public {
        vm.prank(alice);
        staking.deposit{value: 100 ether}();

        vm.prank(operator);
        staking.reportRewards(10 ether);

        // totalPooledEther = 100 + 9.5 = 109.5
        assertEq(staking.totalPooledEther(), 109.5 ether);
    }

    function test_RewardsOnlyOperator() public {
        vm.prank(alice);
        vm.expectRevert("Only TEE operator");
        staking.reportRewards(1 ether);
    }

    // ═══════════════════════ Withdrawals ═══════════════════════

    function test_WithdrawFromBuffer() public {
        vm.prank(alice);
        staking.deposit{value: 10 ether}();

        uint256 balBefore = alice.balance;
        vm.prank(alice);
        staking.requestWithdrawal(5 ether);

        assertEq(alice.balance, balBefore + 5 ether, "Should receive ETH immediately");
        assertEq(staking.balanceOf(alice), 5 ether);
        assertEq(staking.totalPooledEther(), 5 ether);
        assertEq(staking.bufferedEther(), 5 ether);
    }

    function test_WithdrawAfterRewards_GetsMore() public {
        vm.prank(alice);
        staking.deposit{value: 100 ether}();

        vm.prank(operator);
        staking.reportRewards(10 ether);

        // Alice's shares are worth more now
        uint256 ethValue = staking.ethForTeeEth(staking.balanceOf(alice));
        assertGt(ethValue, 100 ether, "Should be worth more after rewards");
    }

    function test_WithdrawQueued_WhenBufferInsufficient() public {
        vm.prank(alice);
        staking.deposit{value: 32 ether}();

        // Operator creates validator, draining buffer
        vm.prank(operator);
        staking.createValidator();
        assertEq(staking.bufferedEther(), 0);

        // Alice tries to withdraw — goes to queue
        vm.prank(alice);
        staking.requestWithdrawal(10 ether);
        assertEq(staking.pendingWithdrawals(), 10 ether);
        assertEq(staking.withdrawalQueueLength(), 1);
    }

    function test_ClaimWithdrawal_AfterValidatorExit() public {
        vm.prank(alice);
        staking.deposit{value: 32 ether}();
        vm.prank(operator);
        staking.createValidator();

        // Alice queues withdrawal
        vm.prank(alice);
        staking.requestWithdrawal(10 ether);

        // Validator exits, returning ETH
        vm.deal(address(staking), 32 ether);
        vm.prank(operator);
        staking.reportValidatorExit(32 ether);

        // Now claim
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        staking.claimWithdrawal(0);
        assertEq(alice.balance, balBefore + 10 ether);
        assertEq(staking.pendingWithdrawals(), 0);
    }

    function test_WithdrawZero_Reverts() public {
        vm.prank(alice);
        vm.expectRevert("Zero amount");
        staking.requestWithdrawal(0);
    }

    function test_WithdrawInsufficientBalance_Reverts() public {
        vm.prank(alice);
        vm.expectRevert("Insufficient teeETH");
        staking.requestWithdrawal(1 ether);
    }

    // ═══════════════════════ ERC-20 Standard ═══════════════════════

    function test_Transfer() public {
        vm.prank(alice);
        staking.deposit{value: 10 ether}();
        vm.prank(alice);
        staking.transfer(bob, 5 ether);
        assertEq(staking.balanceOf(alice), 5 ether);
        assertEq(staking.balanceOf(bob), 5 ether);
    }

    function test_Approve_TransferFrom() public {
        vm.prank(alice);
        staking.deposit{value: 10 ether}();
        vm.prank(alice);
        staking.approve(bob, 3 ether);
        vm.prank(bob);
        staking.transferFrom(alice, carol, 3 ether);
        assertEq(staking.balanceOf(carol), 3 ether);
    }

    function test_Name_Symbol_Decimals() public view {
        assertEq(staking.name(), "TEE Staked Ether");
        assertEq(staking.symbol(), "teeETH");
        assertEq(staking.decimals(), 18);
    }

    // ═══════════════════════ Full Lifecycle ═══════════════════════

    function test_FullLifecycle() public {
        // 1. Alice deposits 64 ETH
        vm.prank(alice);
        staking.deposit{value: 64 ether}();
        assertEq(staking.balanceOf(alice), 64 ether);

        // 2. Operator creates 2 validators
        vm.startPrank(operator);
        staking.createValidator();
        staking.createValidator();
        vm.stopPrank();
        assertEq(staking.activeValidators(), 2);
        assertEq(staking.bufferedEther(), 0);

        // 3. Bob deposits 20 ETH (sits in buffer, < 32)
        vm.prank(bob);
        staking.deposit{value: 20 ether}();
        assertEq(staking.bufferedEther(), 20 ether);
        assertEq(staking.pendingValidators(), 0);

        // 4. Rewards: 2 ETH earned
        vm.prank(operator);
        staking.reportRewards(2 ether);
        // Pool = 84 + 1.9 = 85.9 ETH (treasury gets 0.1 ETH in shares)
        assertEq(staking.totalPooledEther(), 85.9 ether);

        // 5. Exchange rate increased
        uint256 rate = staking.exchangeRate();
        assertGt(rate, 1 ether);

        // 6. Carol deposits after rewards — gets fewer shares
        vm.prank(carol);
        staking.deposit{value: 10 ether}();
        assertLt(staking.balanceOf(carol), 10 ether);

        // 7. Alice withdraws some — buffer has enough
        vm.prank(alice);
        staking.requestWithdrawal(10 ether);
        // She gets more than 10 ETH because rate > 1
        // (10 shares * rate > 10 ETH)
    }
}
