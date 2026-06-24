// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IERC20.sol";

/// @title BridgeEscrow — Ethereum-side bridge contract
/// @notice Holds ERC20 tokens in escrow when users bridge to TEE-Chain.
///         Releases tokens when users bridge back, verified by TEE-5 ECDSA signature.
/// @dev Deployed on Ethereum mainnet (or testnet). Paired with BridgeVault on TEE-Chain.
contract BridgeEscrow {
    // ═══════════════════════ State ═══════════════════════
    /// @notice The ERC20 token being bridged (1:1 with TEE-Chain native coin).
    IERC20 public token;

    /// @notice Admin address (can adjust fee and TEE signer).
    address public admin;

    /// @notice TEE-5's Ethereum address (ECDSA secp256k1 public key).
    /// Used to verify withdrawal approval signatures.
    address public teeSigner;

    /// @notice Bridge fee in token units (default 0.1 tokens = 10^17).
    uint256 public bridgeFee;

    // ═══════════════════════ Per-User Accounting ═══════════════════════
    /// @notice Total tokens deposited by each user for bridging.
    mapping(address => uint256) public totalDeposited;

    /// @notice Total tokens claimed back by each user from bridging.
    mapping(address => uint256) public totalClaimed;

    /// @notice Next deposit nonce per user (monotonically increasing).
    mapping(address => uint256) public depositNonce;

    /// @notice Next claim nonce per user.
    mapping(address => uint256) public claimNonce;

    /// @notice Processed withdrawal hashes (replay protection).
    mapping(bytes32 => bool) public processedWithdrawals;

    // ═══════════════════════ Reentrancy Guard ═══════════════════════
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // ═══════════════════════ Events ═══════════════════════
    event DepositForBridge(
        address indexed user,
        uint256 amount,
        uint256 fee,
        uint256 nonce,
        uint256 timestamp
    );

    event ClaimFromBridge(
        address indexed user,
        uint256 amount,
        uint256 nonce
    );

    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event TeeSignerUpdated(address oldSigner, address newSigner);

    // ═══════════════════════ Constructor ═══════════════════════
    constructor(address _token, address _teeSigner, uint256 _bridgeFee) {
        require(_token != address(0), "Zero token");
        require(_teeSigner != address(0), "Zero signer");
        token = IERC20(_token);
        admin = msg.sender;
        teeSigner = _teeSigner;
        bridgeFee = _bridgeFee;
        _status = _NOT_ENTERED;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    // ═══════════════════════ Bridge IN (deposit) ═══════════════════════

    /// @notice Deposit tokens to bridge to TEE-Chain.
    /// @dev User must approve this contract for `amount` tokens first.
    ///      The fee is deducted from the deposit amount.
    ///      TEE-5 will verify this transaction via RPC and mint native coins.
    /// @param amount Total amount of tokens to deposit (including fee).
    function depositForBridge(uint256 amount) external nonReentrant {
        require(amount > bridgeFee, "Amount must exceed fee");

        // Transfer tokens to escrow
        bool ok = token.transferFrom(msg.sender, address(this), amount);
        require(ok, "Transfer failed");

        uint256 nonce = depositNonce[msg.sender];
        totalDeposited[msg.sender] += amount;
        depositNonce[msg.sender] = nonce + 1;

        emit DepositForBridge(msg.sender, amount, bridgeFee, nonce, block.timestamp);
    }

    // ═══════════════════════ Bridge OUT (claim) ═══════════════════════

    /// @notice Claim tokens after bridging back from TEE-Chain.
    /// @dev User burned coins on TEE-Chain, TEE-5 signed an approval.
    ///      The signature is verified against the registered teeSigner.
    /// @param amount Amount to claim (net, after fee was deducted on TEE-Chain).
    /// @param nonce Withdrawal nonce from TEE-5.
    /// @param signature TEE-5's ECDSA signature (65 bytes: r + s + v).
    function claimFromBridge(
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        require(amount > 0, "Zero amount");
        require(nonce == claimNonce[msg.sender], "Invalid nonce");

        // Construct the message hash (must match TEE-5's signing format)
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender, amount, nonce, "TEE-BRIDGE-WITHDRAWAL"
        ));

        // Verify signature (EIP-191 personal_sign)
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));

        // Replay protection
        require(!processedWithdrawals[ethSignedHash], "Already processed");
        processedWithdrawals[ethSignedHash] = true;

        // Recover signer
        address recovered = recoverSigner(ethSignedHash, signature);
        require(recovered == teeSigner, "Invalid TEE signature");

        // Update accounting
        totalClaimed[msg.sender] += amount;
        claimNonce[msg.sender] = nonce + 1;

        // Release tokens
        bool ok = token.transfer(msg.sender, amount);
        require(ok, "Transfer failed");

        emit ClaimFromBridge(msg.sender, amount, nonce);
    }

    // ═══════════════════════ Admin ═══════════════════════

    /// @notice Update the bridge fee.
    /// @param newFee New fee in token units.
    function setFee(uint256 newFee) external onlyAdmin {
        emit FeeUpdated(bridgeFee, newFee);
        bridgeFee = newFee;
    }

    /// @notice Update the TEE signer address (key rotation).
    /// @param newSigner New TEE-5 ECDSA address.
    function setTeeSigner(address newSigner) external onlyAdmin {
        require(newSigner != address(0), "Zero signer");
        emit TeeSignerUpdated(teeSigner, newSigner);
        teeSigner = newSigner;
    }

    // ═══════════════════════ View ═══════════════════════

    /// @notice Get a user's claimable amount (deposited - claimed).
    function claimable(address user) external view returns (uint256) {
        if (totalDeposited[user] <= totalClaimed[user]) return 0;
        return totalDeposited[user] - totalClaimed[user];
    }

    /// @notice Get the contract's token balance (total escrowed).
    function escrowedBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    // ═══════════════════════ Internal ═══════════════════════

    /// @dev Recover signer from an Ethereum signed message hash.
    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid v value");
        return ecrecover(hash, v, r, s);
    }
}
