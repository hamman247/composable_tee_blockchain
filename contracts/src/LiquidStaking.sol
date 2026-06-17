// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title LiquidStaking - ETH Liquid Staking via TEE-4 Validators
/// @notice Deposits ETH, mints teeETH receipt tokens. 5% rewards → treasury, 95% backs tokens.
/// @dev Follows a shares-based model (like rETH): exchange rate increases as rewards accrue.
///      - Deposit ETH → receive teeETH proportional to current exchange rate
///      - Unstaked ETH sits in contract until 32 ETH available → new validator created
///      - 5% of staking rewards → treasury, 95% → increases teeETH backing
///      - Burn teeETH → receive proportional ETH (from unstaked pool or via withdrawal queue)
contract LiquidStaking {
    // ═══════════════════════ ERC-20: teeETH ═══════════════════════
    string public constant name = "TEE Staked Ether";
    string public constant symbol = "teeETH";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ═══════════════════════ Staking State ═══════════════════════
    /// @notice Treasury receives 5% of all staking rewards.
    address public treasury;

    /// @notice TEE-4 operator address (authorized to report rewards/create validators).
    address public teeOperator;

    /// @notice Total ETH backing all teeETH tokens (deposits + accrued rewards - treasury cut).
    uint256 public totalPooledEther;

    /// @notice ETH sitting in contract waiting to be staked (< 32 ETH threshold or excess).
    uint256 public bufferedEther;

    /// @notice Number of active 32-ETH validators created.
    uint256 public activeValidators;

    /// @notice Total staking rewards ever reported.
    uint256 public totalRewardsAccrued;

    /// @notice Total sent to treasury.
    uint256 public totalTreasuryFees;

    /// @notice Minimum ETH required to create a validator.
    uint256 public constant VALIDATOR_DEPOSIT = 32 ether;

    /// @notice Treasury fee in basis points (500 = 5%).
    uint256 public constant TREASURY_FEE_BPS = 500;

    /// @notice Basis points denominator.
    uint256 public constant BPS_DENOMINATOR = 10_000;

    // ═══════════════════════ Withdrawal Queue ═══════════════════════
    struct WithdrawalRequest {
        address requester;
        uint256 teeEthAmount;
        uint256 ethOwed;
        uint256 requestedAt;
        bool claimed;
    }

    WithdrawalRequest[] public withdrawalQueue;
    uint256 public pendingWithdrawals;

    // ═══════════════════════ Events ═══════════════════════
    event Deposited(address indexed user, uint256 ethAmount, uint256 teeEthMinted);
    event WithdrawalRequested(address indexed user, uint256 teeEthBurned, uint256 ethOwed, uint256 requestId);
    event WithdrawalClaimed(address indexed user, uint256 ethAmount, uint256 requestId);
    event RewardsReported(uint256 totalRewards, uint256 treasuryFee, uint256 poolIncrease);
    event ValidatorCreated(uint256 validatorIndex, uint256 totalActive);
    event ValidatorExited(uint256 validatorIndex, uint256 ethReturned);

    // ═══════════════════════ Constructor ═══════════════════════
    constructor(address _treasury, address _teeOperator) {
        require(_treasury != address(0), "Zero treasury");
        require(_teeOperator != address(0), "Zero operator");
        treasury = _treasury;
        teeOperator = _teeOperator;
    }

    modifier onlyTeeOperator() {
        require(msg.sender == teeOperator, "Only TEE operator");
        _;
    }

    // ═══════════════════════ Deposit (ETH → teeETH) ═══════════════════════

    /// @notice Deposit ETH and receive teeETH tokens.
    /// @dev Exchange rate: teeETH = ETH * totalSupply / totalPooledEther
    ///      First deposit: 1:1 rate.
    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");

        uint256 shares;
        if (totalSupply == 0) {
            // First deposit: 1:1
            shares = msg.value;
        } else {
            // shares = depositETH * totalShares / totalPooledEther
            shares = (msg.value * totalSupply) / totalPooledEther;
        }
        require(shares > 0, "Deposit too small");

        totalPooledEther += msg.value;
        bufferedEther += msg.value;

        _mint(msg.sender, shares);
        emit Deposited(msg.sender, msg.value, shares);
    }

    // ═══════════════════════ Withdrawal (teeETH → ETH) ═══════════════════════

    /// @notice Request withdrawal: burn teeETH, get ETH from buffer or enter queue.
    /// @param teeEthAmount Amount of teeETH to burn.
    function requestWithdrawal(uint256 teeEthAmount) external {
        require(teeEthAmount > 0, "Zero amount");
        require(balanceOf[msg.sender] >= teeEthAmount, "Insufficient teeETH");

        // Calculate ETH owed at current exchange rate
        uint256 ethOwed = (teeEthAmount * totalPooledEther) / totalSupply;

        // Burn the teeETH
        _burn(msg.sender, teeEthAmount);
        totalPooledEther -= ethOwed;

        // Try to fulfill from buffer immediately
        if (bufferedEther >= ethOwed) {
            bufferedEther -= ethOwed;
            (bool ok, ) = msg.sender.call{value: ethOwed}("");
            require(ok, "ETH transfer failed");
            // Push a claimed request for record-keeping
            uint256 rid = withdrawalQueue.length;
            withdrawalQueue.push(WithdrawalRequest({
                requester: msg.sender,
                teeEthAmount: teeEthAmount,
                ethOwed: ethOwed,
                requestedAt: block.timestamp,
                claimed: true
            }));
            emit WithdrawalRequested(msg.sender, teeEthAmount, ethOwed, rid);
            emit WithdrawalClaimed(msg.sender, ethOwed, rid);
        } else {
            // Queue it — fulfilled when validators exit
            uint256 rid = withdrawalQueue.length;
            pendingWithdrawals += ethOwed;
            withdrawalQueue.push(WithdrawalRequest({
                requester: msg.sender,
                teeEthAmount: teeEthAmount,
                ethOwed: ethOwed,
                requestedAt: block.timestamp,
                claimed: false
            }));
            emit WithdrawalRequested(msg.sender, teeEthAmount, ethOwed, rid);
        }
    }

    /// @notice Claim a queued withdrawal (after validator exit funds arrive).
    function claimWithdrawal(uint256 requestId) external {
        require(requestId < withdrawalQueue.length, "Invalid ID");
        WithdrawalRequest storage req = withdrawalQueue[requestId];
        require(req.requester == msg.sender, "Not your request");
        require(!req.claimed, "Already claimed");
        require(bufferedEther >= req.ethOwed, "Insufficient buffer");

        req.claimed = true;
        bufferedEther -= req.ethOwed;
        pendingWithdrawals -= req.ethOwed;

        (bool ok, ) = msg.sender.call{value: req.ethOwed}("");
        require(ok, "ETH transfer failed");
        emit WithdrawalClaimed(msg.sender, req.ethOwed, requestId);
    }

    // ═══════════════════════ Validator Lifecycle (TEE Operator) ═══════════════════════

    /// @notice TEE operator creates a new validator when 32 ETH is buffered.
    /// @dev In production, this sends 32 ETH to the Beacon deposit contract.
    function createValidator() external onlyTeeOperator {
        require(bufferedEther >= VALIDATOR_DEPOSIT, "Need 32 ETH buffered");
        bufferedEther -= VALIDATOR_DEPOSIT;
        activeValidators += 1;
        emit ValidatorCreated(activeValidators, activeValidators);
    }

    /// @notice TEE operator reports staking rewards. 5% → treasury, 95% → pool.
    /// @param rewardAmount Total new rewards earned since last report.
    function reportRewards(uint256 rewardAmount) external onlyTeeOperator {
        require(rewardAmount > 0, "Zero rewards");

        uint256 treasuryFee = (rewardAmount * TREASURY_FEE_BPS) / BPS_DENOMINATOR;
        uint256 poolIncrease = rewardAmount - treasuryFee;

        totalRewardsAccrued += rewardAmount;
        totalTreasuryFees += treasuryFee;
        totalPooledEther += poolIncrease;

        // Treasury fee: mint teeETH shares to treasury at current rate
        if (treasuryFee > 0 && totalPooledEther > 0) {
            uint256 treasuryShares = (treasuryFee * totalSupply) / totalPooledEther;
            if (treasuryShares > 0) {
                _mint(treasury, treasuryShares);
            }
        }

        emit RewardsReported(rewardAmount, treasuryFee, poolIncrease);
    }

    /// @notice TEE operator reports a validator exit, returning ETH to buffer.
    function reportValidatorExit(uint256 ethReturned) external onlyTeeOperator {
        require(activeValidators > 0, "No active validators");
        activeValidators -= 1;
        bufferedEther += ethReturned;
        emit ValidatorExited(activeValidators, ethReturned);
    }

    /// @dev Receive ETH (from validator exits via TEE relay).
    receive() external payable {
        bufferedEther += msg.value;
    }

    // ═══════════════════════ View Functions ═══════════════════════

    /// @notice Current exchange rate: ETH per teeETH (scaled by 1e18).
    function exchangeRate() external view returns (uint256) {
        if (totalSupply == 0) return 1 ether;
        return (totalPooledEther * 1 ether) / totalSupply;
    }

    /// @notice How much ETH a given teeETH amount can be redeemed for.
    function ethForTeeEth(uint256 teeEthAmount) external view returns (uint256) {
        if (totalSupply == 0) return 0;
        return (teeEthAmount * totalPooledEther) / totalSupply;
    }

    /// @notice How much teeETH a deposit of `ethAmount` would receive.
    function teeEthForEth(uint256 ethAmount) external view returns (uint256) {
        if (totalSupply == 0) return ethAmount;
        return (ethAmount * totalSupply) / totalPooledEther;
    }

    /// @notice Number of validators that can be created from current buffer.
    function pendingValidators() external view returns (uint256) {
        return bufferedEther / VALIDATOR_DEPOSIT;
    }

    /// @notice Total withdrawal requests.
    function withdrawalQueueLength() external view returns (uint256) {
        return withdrawalQueue.length;
    }

    // ═══════════════════════ ERC-20 Standard ═══════════════════════

    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ERC20: insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        return _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(from != address(0) && to != address(0), "ERC20: zero address");
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(balanceOf[from] >= amount, "ERC20: burn exceeds balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
}
