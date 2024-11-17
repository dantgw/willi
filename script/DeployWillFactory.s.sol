// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {WillFactory} from "../src/WillFactory.sol";

contract DeployWillFactory is Script {
    function run() public returns (WillFactory) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        WillFactory factory = new WillFactory();
        
        vm.stopBroadcast();
        
        return factory;
    }
} 