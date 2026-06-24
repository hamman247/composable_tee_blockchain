// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/BridgeEscrow.sol";
import "../src/BridgeVault.sol";
import "../src/IERC20.sol";

/// @dev Minimal ERC20 token for testing.
contract MockToken is IERC20 {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient");
        require(allowance[from][msg.sender] >= amount, "Not approved");
        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}


// ═══════════════════════════════════════════════════════════════
// BridgeEscrow Tests
// ═══════════════════════════════════════════════════════════════

contract BridgeEscrowTest is Test {
    MockToken token;
    BridgeEscrow escrow;
    uint256 teePk;
    address teeSigner;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    uint256 fee = 0.1 ether; // 10^17

    function setUp() public {
        token = new MockToken();
        teePk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        teeSigner = vm.addr(teePk);
        escrow = new BridgeEscrow(address(token), teeSigner, fee);

        // Give Alice and Bob tokens
        token.mint(alice, 100 ether);
        token.mint(bob, 50 ether);

        // Fund escrow with tokens for claims
        token.mint(address(escrow), 1000 ether);
    }

    // ── Deposit Tests ──

    function test_depositForBridge() public {
        vm.startPrank(alice);
        token.approve(address(escrow), 10 ether);
        escrow.depositForBridge(10 ether);
        vm.stopPrank();

        assertEq(escrow.totalDeposited(alice), 10 ether);
        assertEq(escrow.depositNonce(alice), 1);
    }

    function test_depositMultiple() public {
        vm.startPrank(alice);
        token.approve(address(escrow), 30 ether);
        escrow.depositForBridge(10 ether);
        escrow.depositForBridge(15 ether);
        vm.stopPrank();

        assertEq(escrow.totalDeposited(alice), 25 ether);
        assertEq(escrow.depositNonce(alice), 2);
    }

    function test_depositTooSmall() public {
        vm.startPrank(alice);
        token.approve(address(escrow), fee);
        vm.expectRevert("Amount must exceed fee");
        escrow.depositForBridge(fee); // exactly fee, should fail
        vm.stopPrank();
    }

    function test_depositNoApproval() public {
        vm.prank(alice);
        vm.expectRevert("Not approved");
        escrow.depositForBridge(10 ether);
    }

    // ── Claim Tests ──

    function test_claimFromBridge() public {
        uint256 amount = 5 ether;
        uint256 nonce = 0;

        // Build the message hash (matches TEE-5 signing format)
        bytes32 messageHash = keccak256(abi.encodePacked(
            alice, amount, nonce, "TEE-BRIDGE-WITHDRAWAL"
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));

        // Sign with TEE key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePk, ethSignedHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 balBefore = token.balanceOf(alice);
        vm.prank(alice);
        escrow.claimFromBridge(amount, nonce, sig);

        assertEq(token.balanceOf(alice), balBefore + amount);
        assertEq(escrow.totalClaimed(alice), amount);
        assertEq(escrow.claimNonce(alice), 1);
    }

    function test_claimWrongNonce() public {
        uint256 amount = 5 ether;
        uint256 wrongNonce = 1; // should be 0

        bytes32 messageHash = keccak256(abi.encodePacked(
            alice, amount, wrongNonce, "TEE-BRIDGE-WITHDRAWAL"
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePk, ethSignedHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert("Invalid nonce");
        escrow.claimFromBridge(amount, wrongNonce, sig);
    }

    function test_claimReplayRejected() public {
        uint256 amount = 5 ether;
        uint256 nonce = 0;

        bytes32 messageHash = keccak256(abi.encodePacked(
            alice, amount, nonce, "TEE-BRIDGE-WITHDRAWAL"
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePk, ethSignedHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        escrow.claimFromBridge(amount, nonce, sig);

        // Replay: nonce mismatch now (claimNonce=1, but signed nonce=0)
        vm.prank(alice);
        vm.expectRevert("Invalid nonce");
        escrow.claimFromBridge(amount, nonce, sig);
    }

    function test_claimFakeSigner() public {
        uint256 fakePk = 0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678;
        uint256 amount = 5 ether;
        uint256 nonce = 0;

        bytes32 messageHash = keccak256(abi.encodePacked(
            alice, amount, nonce, "TEE-BRIDGE-WITHDRAWAL"
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakePk, ethSignedHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert("Invalid TEE signature");
        escrow.claimFromBridge(amount, nonce, sig);
    }

    function test_claimForDifferentUser() public {
        // Bob tries to claim with a signature meant for Alice
        uint256 amount = 5 ether;
        uint256 nonce = 0;

        // Signed for Alice
        bytes32 messageHash = keccak256(abi.encodePacked(
            alice, amount, nonce, "TEE-BRIDGE-WITHDRAWAL"
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePk, ethSignedHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Bob calls (msg.sender = Bob, but sig was for Alice)
        vm.prank(bob);
        vm.expectRevert("Invalid TEE signature");
        escrow.claimFromBridge(amount, nonce, sig);
    }

    // ── Admin Tests ──

    function test_setFee() public {
        escrow.setFee(0.05 ether);
        assertEq(escrow.bridgeFee(), 0.05 ether);
    }

    function test_setFeeNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert("Only admin");
        escrow.setFee(0.05 ether);
    }

    function test_setTeeSigner() public {
        address newSigner = address(0xBEEF);
        escrow.setTeeSigner(newSigner);
        assertEq(escrow.teeSigner(), newSigner);
    }

    function test_setTeeSignerZero() public {
        vm.expectRevert("Zero signer");
        escrow.setTeeSigner(address(0));
    }

    // ── View Tests ──

    function test_claimable() public {
        vm.startPrank(alice);
        token.approve(address(escrow), 20 ether);
        escrow.depositForBridge(10 ether);
        vm.stopPrank();

        assertEq(escrow.claimable(alice), 10 ether);
    }

    function test_claimableAfterClaim() public {
        // Deposit 10
        vm.startPrank(alice);
        token.approve(address(escrow), 10 ether);
        escrow.depositForBridge(10 ether);
        vm.stopPrank();

        // Claim 5
        uint256 amount = 5 ether;
        bytes32 messageHash = keccak256(abi.encodePacked(
            alice, amount, uint256(0), "TEE-BRIDGE-WITHDRAWAL"
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePk, ethSignedHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        escrow.claimFromBridge(amount, 0, sig);

        assertEq(escrow.claimable(alice), 5 ether);
    }

    // ── Sequential Nonce Tests ──

    function test_sequentialClaims() public {
        for (uint256 i = 0; i < 3; i++) {
            uint256 amount = 1 ether;
            bytes32 messageHash = keccak256(abi.encodePacked(
                alice, amount, i, "TEE-BRIDGE-WITHDRAWAL"
            ));
            bytes32 ethSignedHash = keccak256(abi.encodePacked(
                "\x19Ethereum Signed Message:\n32", messageHash
            ));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePk, ethSignedHash);
            bytes memory sig = abi.encodePacked(r, s, v);

            vm.prank(alice);
            escrow.claimFromBridge(amount, i, sig);
        }

        assertEq(escrow.totalClaimed(alice), 3 ether);
        assertEq(escrow.claimNonce(alice), 3);
    }
}


// ═══════════════════════════════════════════════════════════════
// BridgeVault Tests
// ═══════════════════════════════════════════════════════════════

contract BridgeVaultTest is Test {
    BridgeVault vault;
    address alice = address(0xA11CE);
    uint256 fee = 0.1 ether;

    function setUp() public {
        vault = new BridgeVault(fee);
        vm.deal(alice, 100 ether);
    }

    function test_burnForBridge() public {
        vm.prank(alice);
        vault.burnForBridge{value: 5 ether}();

        assertEq(vault.totalBurnedOut(alice), 5 ether);
        assertEq(vault.burnNonce(alice), 1);
        assertEq(vault.totalBurned(), 5 ether);
        assertEq(vault.totalFeesCollected(), fee);
    }

    function test_burnMultiple() public {
        vm.startPrank(alice);
        vault.burnForBridge{value: 3 ether}();
        vault.burnForBridge{value: 2 ether}();
        vm.stopPrank();

        assertEq(vault.totalBurnedOut(alice), 5 ether);
        assertEq(vault.burnNonce(alice), 2);
        assertEq(vault.totalFeesCollected(), fee * 2);
    }

    function test_burnTooSmall() public {
        vm.prank(alice);
        vm.expectRevert("Amount must exceed fee");
        vault.burnForBridge{value: fee}(); // exactly fee
    }

    function test_burnZero() public {
        vm.prank(alice);
        vm.expectRevert("Amount must exceed fee");
        vault.burnForBridge{value: 0}();
    }

    function test_recordBridgeIn() public {
        vault.recordBridgeIn(alice, 10 ether);
        (uint256 bridgedIn, uint256 burnedOut) = vault.userNetBalance(alice);
        assertEq(bridgedIn, 10 ether);
        assertEq(burnedOut, 0);
    }

    function test_recordBridgeInNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert("Only admin");
        vault.recordBridgeIn(alice, 10 ether);
    }

    function test_setFee() public {
        vault.setFee(0.05 ether);
        assertEq(vault.bridgeFee(), 0.05 ether);
    }

    function test_setFeeNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert("Only admin");
        vault.setFee(0.05 ether);
    }

    function test_lockedBalance() public {
        vm.prank(alice);
        vault.burnForBridge{value: 7 ether}();
        assertEq(vault.lockedBalance(), 7 ether);
    }

    function test_userNetBalance() public {
        vm.prank(alice);
        vault.burnForBridge{value: 5 ether}();
        vault.recordBridgeIn(alice, 10 ether);

        (uint256 bridgedIn, uint256 burnedOut) = vault.userNetBalance(alice);
        assertEq(bridgedIn, 10 ether);
        assertEq(burnedOut, 5 ether);
    }

    function test_nonceIncrementsPerUser() public {
        address bob = address(0xB0B);
        vm.deal(bob, 100 ether);

        vm.prank(alice);
        vault.burnForBridge{value: 1 ether}();
        vm.prank(bob);
        vault.burnForBridge{value: 2 ether}();
        vm.prank(alice);
        vault.burnForBridge{value: 1 ether}();

        assertEq(vault.burnNonce(alice), 2);
        assertEq(vault.burnNonce(bob), 1);
    }
}
