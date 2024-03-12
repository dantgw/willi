// This file is part of Modular Account.
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

interface IMultisigPlugin {
    enum FunctionId {
        USER_OP_VALIDATION_OWNER // require owner access
    }

    /// @notice This event is emitted when owners of the account are updated.
    /// @param account The account whose ownership changed.
    /// @param addedOwners The address array of added owners.
    /// @param removedOwners The address array of removed owners.
    /// @param threshold The new threshold.
    event OwnerUpdated(address indexed account, address[] addedOwners, address[] removedOwners, uint256 threshold);

    error ECDSARecoverFailure();
    error EmptyOwnersNotAllowed();
    error InvalidOwner(address owner);
    error InvalidSigOffset();
    error InvalidThreshold();
    error NotAuthorized();
    error OwnerDoesNotExist(address owner);

    /// @notice Update owners of the account, and/or threshold
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param ownersToAdd The address array of owners to be added.
    /// @param ownersToRemove The address array of owners to be removed.
    /// @param newThreshold The new threshold.
    function updateOwnership(address[] memory ownersToAdd, address[] memory ownersToRemove, uint256 newThreshold)
        external;

    /// @notice Gets the EIP712 domain
    /// @dev This implementation is different from typical 712 via its use of msg.sender instead. As such, it
    /// should only be called from the SCAs that has installed this. See ERC-5267.
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );

    /// @notice Check if the signatures are valid for the account.
    /// @param digest The hash of the message.
    /// @param account The account to check the signatures for.
    /// @param signatures The signatures to check.
    /// @return True if the signatures are valid.
    function checkNSignatures(bytes32 digest, address account, bytes calldata signatures)
        external
        view
        returns (bool, uint256);

    /// @notice Check if an address is an owner of `account`.
    /// @param account The account to check.
    /// @param ownerToCheck The owner to check if it is an owner of the provided account.
    /// @return True if the address is an owner of the account.
    function isOwnerOf(address account, address ownerToCheck) external view returns (bool);

    /// @notice Get the owners of `account`, and the threshold.
    /// @param account The account to get the owners of.
    /// @return The addresses of the owners of the account, and the threshold
    function ownershipInfoOf(address account) external view returns (address[] memory, uint256);

    /// @notice Returns the pre-image of the message hash
    /// @dev Assumes that the SCA's implementation of `domainSeparator` is this plugin's
    /// @param account SCA to build the message encoding for
    /// @param message Message that should be encoded.
    /// @return Encoded message.
    function encodeMessageData(address account, bytes memory message) external view returns (bytes memory);

    /// @notice Returns hash of a message that can be signed by owners.
    /// @param account SCA to build the message hash for
    /// @param message Message that should be hashed.
    /// @return Message hash.
    function getMessageHash(address account, bytes memory message) external view returns (bytes32);
}