// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

contract MockModularAccount {
    address[] public owners;
    mapping(address => bool) public isOwner;

    event OwnersUpdated(address[] added, address[] removed);

    constructor(address initialOwner) {
        owners.push(initialOwner);
        isOwner[initialOwner] = true;
    }

    function updateOwners(address[] calldata toAdd, address[] calldata toRemove) external {
        // Only allow current owners to update
        require(isOwner[msg.sender], "Not authorized");

        // Remove owners
        for (uint256 i = 0; i < toRemove.length; i++) {
            require(isOwner[toRemove[i]], "Address not owner");
            isOwner[toRemove[i]] = false;
        }

        // Add new owners
        for (uint256 i = 0; i < toAdd.length; i++) {
            require(toAdd[i] != address(0), "Invalid owner address");
            require(!isOwner[toAdd[i]], "Already owner");
            isOwner[toAdd[i]] = true;
            owners.push(toAdd[i]);
        }

        emit OwnersUpdated(toAdd, toRemove);
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    // Allow the account to receive ETH
    receive() external payable {}
} 