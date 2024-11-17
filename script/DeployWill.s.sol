// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.22;

// import {Script} from "forge-std/Script.sol";
// import {console} from "forge-std/Test.sol";
// import {Will} from "../src/Will.sol";

// contract DeployWill is Script {
//     // Load owner from env
//     address public owner = vm.envAddress("OWNER");
    
//     // Will contract
//     address public willContract;
//     bytes32 public willSalt = vm.envOr("WILL_SALT", bytes32(0));
//     address public expectedWill = vm.envOr("EXPECTED_WILL", address(0));

//     // New constructor arguments
//     address public smartAccount = vm.envAddress("SMART_ACCOUNT");
//     uint256 public proofOfLifePeriod = vm.envUint("PROOF_OF_LIFE_PERIOD");
//     address[] public beneficiaries;

//     function run() public {
//         console.log("******** Deploying Will Contract *********");
//         console.log("Chain: ", block.chainid);

//         // Load beneficiaries from environment
//         string memory beneficiariesRaw = vm.envString("BENEFICIARIES");
//         string[] memory beneficiaryStrings = vm.parseJsonStringArray(beneficiariesRaw);
//         beneficiaries = new address[](beneficiaryStrings.length);
//         for (uint i = 0; i < beneficiaryStrings.length; i++) {
//             beneficiaries[i] = vm.parseAddress(beneficiaryStrings[i]);
//         }

//         vm.startBroadcast();

//         // Deploy Will contract with constructor arguments
//         willContract = address(new Will{salt: willSalt}(
//             smartAccount,
//             proofOfLifePeriod,
//             beneficiaries
//         ));

//         console.log("New Will Contract: ", willContract);
//         console.log("******** Deploy Done! *********");
//         vm.stopBroadcast();
//     }
// } 