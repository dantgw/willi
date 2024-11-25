// pragma solidity ^0.8.22;

// import {Script} from "forge-std/Script.sol";
// import {console} from "forge-std/Test.sol";

// import {IEntryPoint as I4337EntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

// import {UpgradeableModularAccount} from "@alchemy/modular-account/src/account/UpgradeableModularAccount.sol";
// import {IEntryPoint} from "@alchemy/modular-account/src/interfaces/erc4337/IEntryPoint.sol";
// import {BasePlugin} from "@alchemy/modular-account/src/plugins/BasePlugin.sol";

// import {MultisigModularAccountFactory} from "../src/MultisigModularAccountFactory.sol";
// import {MultisigPlugin} from "../src/MultisigPlugin.sol";

// contract Deploy is Script {
//     // Load entrypoint from env
//     address public entryPointAddr = vm.envAddress("ENTRYPOINT");
//     IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

//     // Load factory owner from env
//     address public owner = vm.envAddress("OWNER");

//     // Load core contract from env
//     address public maImpl = vm.envAddress("MA_IMPL");

//     // Multisig plugin
//     address public multisigPlugin = vm.envOr("MULTISIG_PLUGIN", address(0));
//     bytes32 public multisigPluginSalt = vm.envOr("MULTISIG_PLUGIN_SALT", bytes32(0));
//     bytes32 public multisigPluginManifestHash;
//     address public expectedMultisigPlugin = vm.envOr("EXPECTED_MULTISIG_PLUGIN", address(0));

//     // Factory
//     address public factory;
//     bytes32 public factorySalt = vm.envOr("FACTORY_SALT", bytes32(0));
//     address public expectedFactory = vm.envOr("EXPECTED_FACTORY", address(0));

//     function run() public {
//         console.log("******** Deploying *********");
//         console.log("Chain: ", block.chainid);
//         console.log("EP: ", entryPointAddr);
//         console.log("Factory owner: ", owner);

//         vm.startBroadcast();

//         // Deploy multisig plugin, and set plugin hash
//         if (multisigPlugin == address(0)) {
//             multisigPlugin = address(new MultisigPlugin{salt: multisigPluginSalt}(address(entryPoint)));

//             if (expectedMultisigPlugin != address(0)) {
//                 require(multisigPlugin == expectedMultisigPlugin, "MultisigPlugin address mismatch");
//             }
//             console.log("New MultisigPlugin: ", multisigPlugin);
//         } else {
//             console.log("Exist MultisigPlugin: ", multisigPlugin);
//         }
//         multisigPluginManifestHash = keccak256(abi.encode(BasePlugin(multisigPlugin).pluginManifest()));

//         // Deploy factory
//         factory = address(
//             new MultisigModularAccountFactory{salt: factorySalt}(
//                 owner, multisigPlugin, maImpl, multisigPluginManifestHash, entryPoint
//             )
//         );

//         if (expectedFactory != address(0)) {
//             require(factory == expectedFactory, "MultisigModularAccountFactory address mismatch");
//         }
//         _addStakeForFactory(factory, entryPoint);
//         console.log("New MultisigModularAccountFactory: ", factory);

//         console.log("******** Deploy Done! *********");
//         vm.stopBroadcast();
//     }

//     function _addStakeForFactory(address factoryAddr, IEntryPoint anEntryPoint) internal {
//         uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(86400)));
//         uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT");
//         uint256 currentStakedAmount = I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake;
//         uint256 stakeAmount = requiredStakeAmount - currentStakedAmount;
//         // since all factory share the same addStake method, it does not matter which contract we use to cast the
//         // address
//         MultisigModularAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount}(unstakeDelaySec, stakeAmount);
//         console.log("******** Add Stake Verify *********");
//         console.log("Staked factory: ", factoryAddr);
//         console.log("Stake amount: ", I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake);
//         console.log(
//             "Unstake delay: ", I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).unstakeDelaySec
//         );
//         console.log("******** Stake Verify Done *********");
//     }
// }
