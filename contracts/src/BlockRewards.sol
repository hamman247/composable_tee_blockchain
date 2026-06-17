// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./TEERegistry.sol";

/// @title BlockRewards - Calculates and distributes block rewards per TEE constraints
contract BlockRewards {
    TEERegistry public teeRegistry;
    address public systemCaller;

    event RewardsDistributed(bytes32 indexed teeId, address operator, uint256 amount, uint256 blockNumber);

    modifier onlySystem() {
        require(msg.sender == systemCaller, "BlockRewards: unauthorized caller");
        _;
    }

    constructor(address _registry, address _systemCaller) {
        teeRegistry = TEERegistry(_registry);
        systemCaller = _systemCaller;
    }

    /// @notice Distribute block rewards (called during block finalization)
    function distributeRewards(
        bytes32 teeId,
        address operator,
        uint256 amount
    ) external payable onlySystem {
        require(teeRegistry.isMiningEligible(teeId), "TEE not mining eligible");
        (, , , , , , , , , uint256 maxReward, ,) = teeRegistry.tees(teeId);
        require(amount <= maxReward, "Exceeds max reward");
        require(msg.value >= amount, "Insufficient funds");

        payable(operator).transfer(amount);
        emit RewardsDistributed(teeId, operator, amount, block.number);

        // Return excess
        if (msg.value > amount) {
            payable(msg.sender).transfer(msg.value - amount);
        }
    }

    /// @notice Distribute proportional rewards to multiple operators (for TEE-2)
    function distributeProportional(
        bytes32 teeId,
        address[] calldata operators,
        uint256[] calldata amounts
    ) external payable onlySystem {
        require(operators.length == amounts.length, "Length mismatch");
        require(teeRegistry.isMiningEligible(teeId), "TEE not mining eligible");

        uint256 total = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }
        (, , , , , , , , , uint256 maxReward, ,) = teeRegistry.tees(teeId);
        require(total <= maxReward, "Total exceeds max reward");
        require(msg.value >= total, "Insufficient funds");

        for (uint256 i = 0; i < operators.length; i++) {
            payable(operators[i]).transfer(amounts[i]);
            emit RewardsDistributed(teeId, operators[i], amounts[i], block.number);
        }

        if (msg.value > total) {
            payable(msg.sender).transfer(msg.value - total);
        }
    }
}
