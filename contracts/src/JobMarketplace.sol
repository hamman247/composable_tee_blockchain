// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title JobMarketplace - User-submitted TEE job registration and payment pools
contract JobMarketplace {
    struct Job {
        bytes32 codeHash;
        bytes config;
        address creator;
        uint256 totalDeposited;
        bool active;
    }

    struct Deposit {
        address depositor;
        uint256 amount;
        uint256 lockUpEnd;
        bool withdrawn;
    }

    mapping(bytes32 => Job) public jobs;
    mapping(bytes32 => Deposit[]) public deposits;
    bytes32[] public jobIds;
    address public governance;

    event JobRegistered(bytes32 indexed jobId, bytes32 codeHash, address creator);
    event Deposited(bytes32 indexed jobId, address depositor, uint256 amount, uint256 lockUpEnd);
    event Withdrawn(bytes32 indexed jobId, uint256 depositId, address depositor, uint256 amount);
    event PayoutClaimed(bytes32 indexed jobId, address[] operators, uint256[] amounts);

    modifier onlyGovernance() {
        require(msg.sender == governance, "Only governance");
        _;
    }

    constructor(address _governance) {
        governance = _governance;
    }

    /// @notice Register a new TEE job (does NOT qualify for mining by default)
    function registerJob(bytes32 codeHash, bytes calldata config) external returns (bytes32) {
        bytes32 jobId = keccak256(abi.encodePacked(codeHash, msg.sender, block.timestamp));
        require(jobs[jobId].codeHash == bytes32(0), "Job exists");

        jobs[jobId] = Job({
            codeHash: codeHash,
            config: config,
            creator: msg.sender,
            totalDeposited: 0,
            active: true
        });
        jobIds.push(jobId);
        emit JobRegistered(jobId, codeHash, msg.sender);
        return jobId;
    }

    /// @notice Deposit native tokens into a per-TEE payment pool
    function deposit(bytes32 jobId, uint256 lockUpPeriod) external payable {
        require(jobs[jobId].active, "Job not active");
        require(msg.value > 0, "Must deposit > 0");

        deposits[jobId].push(Deposit({
            depositor: msg.sender,
            amount: msg.value,
            lockUpEnd: block.timestamp + lockUpPeriod,
            withdrawn: false
        }));
        jobs[jobId].totalDeposited += msg.value;
        emit Deposited(jobId, msg.sender, msg.value, block.timestamp + lockUpPeriod);
    }

    /// @notice Withdraw unclaimed funds after lock-up expires
    function withdraw(bytes32 jobId, uint256 depositId) external {
        Deposit storage d = deposits[jobId][depositId];
        require(d.depositor == msg.sender, "Not depositor");
        require(block.timestamp >= d.lockUpEnd, "Lock-up not expired");
        require(!d.withdrawn, "Already withdrawn");

        d.withdrawn = true;
        jobs[jobId].totalDeposited -= d.amount;
        payable(msg.sender).transfer(d.amount);
        emit Withdrawn(jobId, depositId, msg.sender, d.amount);
    }

    /// @notice Claim payout for operators (governance-only, called during validated block processing)
    /// @dev Previously this accepted a TEE signature parameter but never verified it.
    ///      Now restricted to governance to ensure payouts only occur through validated blocks.
    function claimPayout(
        bytes32 jobId,
        address[] calldata operators,
        uint256[] calldata amounts
    ) external onlyGovernance {
        require(operators.length == amounts.length, "Length mismatch");
        Job storage job = jobs[jobId];
        require(job.active, "Job not active");

        uint256 total = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }
        require(total <= job.totalDeposited, "Insufficient pool");
        job.totalDeposited -= total;

        for (uint256 i = 0; i < operators.length; i++) {
            payable(operators[i]).transfer(amounts[i]);
        }
        emit PayoutClaimed(jobId, operators, amounts);
    }

    function getDepositCount(bytes32 jobId) external view returns (uint256) {
        return deposits[jobId].length;
    }

    function getJobCount() external view returns (uint256) {
        return jobIds.length;
    }
}
