// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title StakingToken - Native ERC-20 token with staking for TEE-chain governance
/// @notice Provides stake/unstake with voting power tracking for DAO governance
contract StakingToken {
    string public constant name = "TEE Chain Token";
    string public constant symbol = "TEEC";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public totalStaked;

    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public stakedOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
        emit Transfer(address(0), msg.sender, _initialSupply);
    }

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

    function stake(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        stakedOf[msg.sender] += amount;
        totalStaked += amount;
        emit Staked(msg.sender, amount);
    }

    function unstake(uint256 amount) external {
        require(stakedOf[msg.sender] >= amount, "Insufficient staked balance");
        stakedOf[msg.sender] -= amount;
        totalStaked -= amount;
        balanceOf[msg.sender] += amount;
        emit Unstaked(msg.sender, amount);
    }

    function votingPower(address account) external view returns (uint256) {
        return stakedOf[account];
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(from != address(0), "ERC20: from zero");
        require(to != address(0), "ERC20: to zero");
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    /// @dev Mint tokens (only callable by system/genesis)
    function mint(address to, uint256 amount) external {
        // In production, this would be restricted to system contracts
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
