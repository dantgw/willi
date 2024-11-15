// This file is part of Multisig Plugin.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {UUPSUpgradeable} from "@alchemy/modular-account/ext/UUPSUpgradeable.sol";
import {
    PluginManifest,
    PluginMetadata,
    ManifestFunction,
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    SelectorPermission
} from "@alchemy/modular-account/src/interfaces/IPlugin.sol";
import {BasePlugin} from "@alchemy/modular-account/src/plugins/BasePlugin.sol";
import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@alchemy/modular-account/src/libraries/AssociatedLinkedListSetLib.sol";
import {UserOperation} from "@alchemy/modular-account/src/interfaces/erc4337/UserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_PASSED} from "@alchemy/modular-account/src/libraries/Constants.sol";
import {CastLib} from "@alchemy/modular-account/src/helpers/CastLib.sol";
import {IStandardExecutor} from "@alchemy/modular-account/src/interfaces/IStandardExecutor.sol";
import {UpgradeableModularAccount} from "@alchemy/modular-account/src/account/UpgradeableModularAccount.sol";

import {IWillPlugin} from "./IWillPlugin.sol";

/// @title Will Plugin
/// @author Alchemy
/// @notice This plugin adds a k of n threshold ownership scheme to a ERC6900 smart contract account
/// @notice Multisig verification impl is derived from [Safe](https://github.com/safe-global/safe-smart-account)
///
/// It supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature
/// validation for both validating the signature on user operations and in
/// exposing its own `isValidSignature` method. This only works when the owner of
/// modular account also support ERC-1271.
///
/// ERC-4337's bundler validation rules limit the types of contracts that can be
/// used as owners to validate user operation signatures. For example, the
/// contract's `isValidSignature` function may not use any forbidden opcodes
/// such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967
/// proxy as it accesses a constant implementation slot not associated with
/// the account, violating storage access rules. This also means that the
/// owner of a modular account may not be another modular account if you want to
/// send user operations through a bundler.

contract WillPlugin is BasePlugin, IWillPlugin, IERC1271 {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using ECDSA for bytes32;
    using SafeCast for uint256;

    string internal constant _NAME = "Will Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Willy";

    bytes32 private constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant _HASHED_NAME = keccak256(bytes(_NAME));
    bytes32 private constant _HASHED_VERSION = keccak256(bytes(_VERSION));
    bytes32 private immutable _SALT = bytes32(bytes20(address(this)));

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_MAGIC_VALUE_FAILURE = 0xffffffff;

    bytes32 private constant _MULTISIG_PLUGIN_TYPEHASH = keccak256("AlchemyMultisigMessage(bytes message)");

    AssociatedLinkedListSet internal _owners;
    mapping(address => OwnershipMetadata) internal _ownerMetadata;
    address public immutable ENTRYPOINT;

    error OwnerStillAlive();
    error ProofOfLifePeriodTooShort();
    error NotBeneficiary();
    event ProofOfLifeUpdated(address indexed account, uint256 lastActiveTime, uint256 proofOfLifePeriod);
    event ProofOfLifePeriodSet(address indexed account, uint256 proofOfLifePeriod);

    /// @notice Metadata of the ownership of an account.
    /// @param numOwners number of owners on the account
    /// @param lastActiveTime last transaction time
    /// @param proofOfLifePeriod periodicity of transactions to prove
    struct OwnershipMetadata {
        uint128 numOwners;
        uint256 lastActiveTime;    
        uint256 proofOfLifePeriod; 
    }

    constructor(address entryPoint) {
        ENTRYPOINT = entryPoint;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IWillPlugin
    /// @dev If an owner is present in both beneficiariesToAdd and beneficiariesToRemove, it will be added as owner.
    /// The owner array cannot have 0 or duplicated addresses.
    function updateBeneficiaries(address[] memory beneficiariesToAdd, address[] memory beneficiariesToRemove)
        public
        isInitialized(msg.sender)
    {
        // update owners array
        uint256 toRemoveLen = beneficiariesToRemove.length;
        for (uint256 i = 0; i < toRemoveLen; ++i) {
            if (!_owners.tryRemove(msg.sender, CastLib.toSetValue(beneficiariesToRemove[i]))) {
                revert OwnerDoesNotExist(beneficiariesToRemove[i]);
            }
        }

        _addBeneficiariesOrRevert(msg.sender, beneficiariesToAdd);

        OwnershipMetadata storage metadata = _ownerMetadata[msg.sender];
        uint256 numOwners = metadata.numOwners;

        uint256 toAddLen = beneficiariesToAdd.length;
        if (toAddLen != toRemoveLen) {
            numOwners = numOwners - toRemoveLen + toAddLen;
            if (numOwners == 0) {
                revert EmptyOwnersNotAllowed();
            }
            metadata.numOwners = numOwners.toUint128();
        }

        emit OwnerUpdated(msg.sender, beneficiariesToAdd, beneficiariesToRemove);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃  Execution view functions   ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IWillPlugin
    function eip712Domain()
        public
        view
        override
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (
            hex"1f", // 11111 indicate salt field is also used
            _NAME,
            _VERSION,
            block.chainid,
            msg.sender,
            _SALT,
            new uint256[](0)
        );
    }

    /// @inheritdoc IERC1271
function isValidSignature(bytes32 digest, bytes memory signature) external view override returns (bytes4) {
    bool isAlive = checkIsAlive(msg.sender);
    if (!isAlive) {
        return _1271_MAGIC_VALUE_FAILURE;
    }
    
    address signer = ECDSA.recover(digest, signature);
    return signer == msg.sender ? _1271_MAGIC_VALUE : _1271_MAGIC_VALUE_FAILURE;
}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        address[] memory beneficiariesToRemove = CastLib.toAddressArray(_owners.getAll(msg.sender));
        _owners.clear(msg.sender);
        _ownerMetadata[msg.sender] = OwnershipMetadata(0, 0, 0);
        emit OwnerUpdated(msg.sender, new address[](0), beneficiariesToRemove);
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_OWNER)) {
            // UserOp.sig format:
            // 0-32: upperLimitPreVerificationGas
            // 32-64: upperLimitMaxFeePerGas
            // 64-96: upperLimitMaxPriorityFeePerGas
            // 96-96+n: k signatures, each sig is 65 bytes each (so n = 65 * k)
            // 96+n-: contract signatures if any
            if (userOp.signature.length < 96) {
                revert InvalidSigLength();
            }

            (
                uint256 upperLimitPreVerificationGas,
                uint256 upperLimitMaxFeePerGas,
                uint256 upperLimitMaxPriorityFeePerGas
            ) = abi.decode(userOp.signature[0:96], (uint256, uint256, uint256));

            bytes32 actualDigest = userOpHash.toEthSignedMessageHash();
            bytes32 upperLimitDigest = (
                upperLimitPreVerificationGas == userOp.preVerificationGas
                    && upperLimitMaxFeePerGas == userOp.maxFeePerGas
                    && upperLimitMaxPriorityFeePerGas == userOp.maxPriorityFeePerGas
            )
                ? actualDigest
                : _getUserOpHash(
                    userOp, upperLimitPreVerificationGas, upperLimitMaxFeePerGas, upperLimitMaxPriorityFeePerGas
                ).toEthSignedMessageHash();
            (bool success) = checkIsAlive( msg.sender);

            // make sure userOp doesnt use more than the max fees
            // we revert here as its better DevEx over silently failing in case a bad dummy sig is used
            if (upperLimitPreVerificationGas < userOp.preVerificationGas) {
                revert InvalidPreVerificationGas();
            }
            if (upperLimitMaxFeePerGas < userOp.maxFeePerGas) {
                revert InvalidMaxFeePerGas();
            }
            if (upperLimitMaxPriorityFeePerGas < userOp.maxPriorityFeePerGas) {
                revert InvalidMaxPriorityFeePerGas();
            }
            if (success) {
                // Update last active time when owner performs valid transactions
                _ownerMetadata[msg.sender].lastActiveTime = block.timestamp;
                emit ProofOfLifeUpdated(msg.sender, block.timestamp, _ownerMetadata[msg.sender].proofOfLifePeriod);
            }
            return success ? SIG_VALIDATION_PASSED : SIG_VALIDATION_FAILED;
        }

        revert NotImplemented(msg.sig, functionId);
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](3);
        manifest.executionFunctions[0] = this.updateBeneficiaries.selector;
        manifest.executionFunctions[1] = this.eip712Domain.selector;
        manifest.executionFunctions[2] = this.isValidSignature.selector;

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
            dependencyIndex: 0 // Unused.
        });

        // Update Modular Account's native functions to use userOpValidationFunction provided by this plugin
        // The view functions `isValidSignature` and `eip712Domain` are excluded from being assigned a user
        // operation validation function since they should only be called via the runtime path.
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](6);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.updateBeneficiaries.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.installPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory alwaysRevertFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: 0,
            dependencyIndex: 0 // Unused.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](8);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.isValidSignature.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.eip712Domain.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.updateBeneficiaries.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.installPlugin.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
            associatedFunction: alwaysRevertFunction
        });
        manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: alwaysRevertFunction
        });

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Ownership";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.updateBeneficiaries.selector,
            permissionDescription: modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IWillPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IWillPlugin
    function checkIsAlive(
        address account
    ) public view returns (bool success) {
        // TODO: Change to checking timestamp.
        return true;
    }

    /// @inheritdoc IWillPlugin
    function isBeneficiaryOf(address account, address ownerToCheck) external view returns (bool) {
        return _owners.contains(account, CastLib.toSetValue(ownerToCheck));
    }

    /// @inheritdoc IWillPlugin
    function beneficiaryInfoOf(address account) external view returns (address[] memory) {
        return (CastLib.toAddressArray(_owners.getAll(account)));
    }

    /// @inheritdoc IWillPlugin
    function encodeMessageData(address account, bytes memory message) public view override returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encode(_MULTISIG_PLUGIN_TYPEHASH, keccak256(message)));
        return abi.encodePacked("\x19\x01", _domainSeparator(account), messageHash);
    }

    /// @inheritdoc IWillPlugin
    function getMessageHash(address account, bytes memory message) public view override returns (bytes32) {
        return keccak256(encodeMessageData(account, message));
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal Functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    /// @dev The owner array cannot have 0 or duplicated addresses.
    function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
        _ownerMetadata[msg.sender] = OwnershipMetadata({
        numOwners: 0,
        lastActiveTime: block.timestamp,
        proofOfLifePeriod: 0  // 0 means no period set yet
    });
    }

    /// @dev Helper function to get a 65 byte signature from a multi-signature
    /// @dev Functions using this must make sure the signature is long enough to contain k * 65 bytes
    function _signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        assembly ("memory-safe") {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }

    function _domainSeparator(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, block.chainid, account, _SALT));
    }

    function _addBeneficiariesOrRevert(address account, address[] memory beneficiariesToAdd) internal {
        uint256 len = beneficiariesToAdd.length;
        for (uint256 i = 0; i < len; ++i) {
            if (!_owners.tryAdd(account, CastLib.toSetValue(beneficiariesToAdd[i]))) {
                revert InvalidOwner(beneficiariesToAdd[i]);
            }
        }
    }

    /// @inheritdoc BasePlugin
    function _isInitialized(address account) internal view override returns (bool) {
        return !_owners.isEmpty(account);
    }

    function _getUserOpHash(
        UserOperation calldata userOp,
        uint256 upperLimitPreVerificationGas,
        uint256 upperLimitMaxFeePerGas,
        uint256 upperLimitMaxPriorityFeePerGas
    ) internal view returns (bytes32) {
        address sender;
        assembly ("memory-safe") {
            sender := calldataload(userOp)
        }
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = _calldataKeccak(userOp.initCode);
        bytes32 hashCallData = _calldataKeccak(userOp.callData);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = upperLimitPreVerificationGas;
        uint256 maxFeePerGas = upperLimitMaxFeePerGas;
        uint256 maxPriorityFeePerGas = upperLimitMaxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = _calldataKeccak(userOp.paymasterAndData);

        bytes32 userOpHash = keccak256(
            abi.encode(
                sender,
                nonce,
                hashInitCode,
                hashCallData,
                callGasLimit,
                verificationGasLimit,
                preVerificationGas,
                maxFeePerGas,
                maxPriorityFeePerGas,
                hashPaymasterAndData
            )
        );

        return keccak256(abi.encode(userOpHash, ENTRYPOINT, block.chainid));
    }

    function _calldataKeccak(bytes calldata data) internal pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }
}
