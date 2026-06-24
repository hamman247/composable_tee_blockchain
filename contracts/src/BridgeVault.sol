// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BridgeVault — TEE-Chain-side bridge contract
/// @notice Users send native gas coins here to burn them and bridge back to Ethereum.
///         The TEE-5 monitors burns and signs withdrawal approvals for the Ethereum side.
/// @dev Deployed on TEE-Chain. Paired with BridgeEscrow on Ethereum.
contract BridgeVault {
    // ═══════════════════════ State ═══════════════════════
    /// @notice Admin address (can adjust fee).
    address public admin;

    /// @notice Bridge fee in native coin units (default 0.1 coins = 10^17 wei).
    uint256 public bridgeFee;

    // ═══════════════════════ Per-User Accounting ═══════════════════════
    /// @notice Total coins bridged in (minted) to each user from Ethereum.
    mapping(address => uint256) public totalBridgedIn;

    /// @notice Total coins burned by each user for bridging back to Ethereum.
    mapping(address => uint256) public totalBurnedOut;

    /// @notice Next burn nonce per user.
    mapping(address => uint256) public burnNonce;

    /// @notice Total coins burned (destroyed) across all users.
    uint256 public totalBurned;

    /// @notice Total fees collected.
    uint256 public totalFeesCollected;

    // ═══════════════════════ Events ═══════════════════════
    event BurnForBridge(
        address indexed user,
        uint256 grossAmount,
        uint256 netAmount,
        uint256 fee,
        uint256 nonce,
        uint256 timestamp
    );

    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event BridgedIn(address indexed user, uint256 amount);

    // ═══════════════════════ Constructor ═══════════════════════
    constructor(uint256 _bridgeFee) {
        admin = msg.sender;
        bridgeFee = _bridgeFee;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    // ═══════════════════════ Bridge OUT (burn) ═══════════════════════

    /// @notice Burn native gas coins to bridge back to Ethereum.
    /// @dev The sent ETH is permanently locked in this contract (burned).
    ///      After 5 minutes, the user can query TEE-5 for a signed withdrawal
    ///      approval to claim ERC20 tokens on the BridgeEscrow contract.
    function burnForBridge() external payable {
        require(msg.value > bridgeFee, "Amount must exceed fee");

        uint256 netAmount = msg.value - bridgeFee;
        uint256 nonce = burnNonce[msg.sender];

        totalBurnedOut[msg.sender] += msg.value;
        burnNonce[msg.sender] = nonce + 1;
        totalBurned += msg.value;
        totalFeesCollected += bridgeFee;

        emit BurnForBridge(msg.sender, msg.value, netAmount, bridgeFee, nonce, block.timestamp);
    }

    // ═══════════════════════ Bridge IN (record) ═══════════════════════

    /// @notice Record that a user received bridged-in coins (called by TEE operator).
    /// @dev This is for accounting only — the actual mint happens at the consensus level.
    function recordBridgeIn(address user, uint256 amount) external onlyAdmin {
        totalBridgedIn[user] += amount;
        emit BridgedIn(user, amount);
    }

    // ═══════════════════════ Admin ═══════════════════════

    /// @notice Update the bridge fee.
    function setFee(uint256 newFee) external onlyAdmin {
        emit FeeUpdated(bridgeFee, newFee);
        bridgeFee = newFee;
    }

    // ═══════════════════════ View ═══════════════════════

    /// @notice Get a user's net bridge balance.
    function userNetBalance(address user) external view returns (uint256 bridgedIn, uint256 burnedOut) {
        bridgedIn = totalBridgedIn[user];
        burnedOut = totalBurnedOut[user];
    }

    /// @notice Total ETH locked (burned) in the contract.
    function lockedBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
