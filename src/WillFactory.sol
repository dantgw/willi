// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./Will.sol";

contract WillFactory {
    event WillCreated(address indexed willAddress, address indexed owner);

    function createWill() external returns (address) {
        Will will = new Will();
        will.transferOwnership(msg.sender);
        
        emit WillCreated(address(will), msg.sender);
        return address(will);
    }
} 