// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/Test.sol";
import {Will} from "../src/Will.sol";

contract DeployWill is Script {
    // Load owner from env
    address public owner = vm.envAddress("OWNER");
    
    // Will contract
    address public willContract;
    bytes32 public willSalt = vm.envOr("WILL_SALT", bytes32(0));
    address public expectedWill = vm.envOr("EXPECTED_WILL", address(0));

    function run() public {
        console.log("******** Deploying Will Contract *********");
        console.log("Chain: ", block.chainid);
        // console.log("Owner: ", owner);

        vm.startBroadcast();

        // Deploy Will contract
        willContract = address(new Will{salt: willSalt}());

        // if (expectedWill != address(0)) {
        //     require(willContract == expectedWill, "Will contract address mismatch");
        // }
        console.log("New Will Contract: ", willContract);

        console.log("******** Deploy Done! *********");
        vm.stopBroadcast();
    }
} 