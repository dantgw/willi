// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Will is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public lastActiveTime;
    uint256 public proofOfLifePeriod;
    address public smartAccount;

    address[] public beneficiaries;

    event PeriodSet(uint256 newPeriod);
    event ProofOfLife(uint256 timestamp);
    event FundsWithdrawn(address indexed to, uint256 amount);
    event SmartAccountSet(address indexed smartAccount);
    event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);
    event BeneficiariesUpdated(address[] beneficiaries);
    event AccountClaimed(address[] newOwners);

    modifier onlyBeneficiary() {
        bool isABeneficiary = false;
        for (uint256 i = 0; i < beneficiaries.length; i++) {
            if (beneficiaries[i] == msg.sender) {
                isABeneficiary = true;
                break;
            }
        }
        require(isABeneficiary, "Will: caller is not a beneficiary");
        _;
    }

    modifier onlyAfterDead() {
        require(block.timestamp > lastActiveTime + proofOfLifePeriod, "Will: owner is still active");
        _;
    }

    constructor(address _smartAccount) Ownable() {
        lastActiveTime = block.timestamp;
        proofOfLifePeriod = 365 days;
        smartAccount = _smartAccount;
    }

    function setPeriod(uint256 newPeriod) public onlyOwner {
        require(newPeriod > 0, "Will: period must be greater than 0");
        proofOfLifePeriod = newPeriod;
        emit PeriodSet(newPeriod);
    }

    function alive() public onlyOwner {
        lastActiveTime = block.timestamp;
        emit ProofOfLife(block.timestamp);
    }

    function setSmartAccount(address _smartAccount) public onlyOwner {
        require(_smartAccount != address(0), "Will: invalid smart account address");
        smartAccount = _smartAccount;
        emit SmartAccountSet(_smartAccount);
    }

    function setBeneficiaries(address[] calldata _beneficiaries) public onlyOwner {
        require(_beneficiaries.length > 0, "Will: empty beneficiaries array");

        // Clear existing beneficiaries
        delete beneficiaries;

        // Add new beneficiaries
        for (uint256 i = 0; i < _beneficiaries.length; i++) {
            require(_beneficiaries[i] != address(0), "Will: invalid beneficiary address");
            beneficiaries.push(_beneficiaries[i]);
        }

        emit BeneficiariesUpdated(_beneficiaries);
    }

    function claimAccount() public nonReentrant whenNotPaused onlyBeneficiary onlyAfterDead {
        require(beneficiaries.length > 0, "Will: no beneficiaries set");
        require(smartAccount != address(0), "Will: smart account not set");
        address[] memory emptyArray = new address[](0);

        // Update the function call to match the expected signature
        (bool success, bytes memory data) =
            smartAccount.call(abi.encodeWithSignature("updateOwners(address[],address[])", beneficiaries, emptyArray));

        if (!success) {
            if (data.length > 0) {
                assembly {
                    let ptr := mload(0x40)
                    let size := returndatasize()
                    returndatacopy(ptr, 0, size)
                    revert(ptr, size)
                }
            }
            revert("Will: ownership transfer failed");
        }

        emit AccountClaimed(beneficiaries);
    }

    function adminTestClaimAccount() public nonReentrant whenNotPaused {
        address[] memory emptyArray = new address[](0);

        // Update the function call to match the expected signature
        (bool success, bytes memory data) =
            smartAccount.call(abi.encodeWithSignature("updateOwners(address[],address[])", beneficiaries, emptyArray));

        if (!success) {
            if (data.length > 0) {
                assembly {
                    let ptr := mload(0x40)
                    let size := returndatasize()
                    returndatacopy(ptr, 0, size)
                    revert(ptr, size)
                }
            }
            revert("Will: ownership transfer failed");
        }

        emit AccountClaimed(beneficiaries);
    }

    /// @dev Pause the contract
    function pause() public onlyOwner {
        _pause();
    }

    /// @dev Unpause the contract
    function unpause() public onlyOwner {
        _unpause();
    }

    /// @notice Returns the time remaining until the will can be executed
    /// @return The number of seconds remaining, or 0 if the will can be executed
    function timeUntilWillExecution() public view returns (uint256) {
        uint256 deadline = lastActiveTime + proofOfLifePeriod;
        if (block.timestamp >= deadline) {
            return 0;
        }
        return deadline - block.timestamp;
    }

    /// @notice Returns whether the will can be executed
    /// @return True if the will can be executed (owner is considered inactive)
    function isWillExecutable() public view returns (bool) {
        return block.timestamp > lastActiveTime + proofOfLifePeriod;
    }

    /// @notice Returns all current beneficiaries
    /// @return Array of beneficiary addresses
    function getBeneficiaries() public view returns (address[] memory) {
        address[] memory result = new address[](beneficiaries.length);
        for (uint256 i = 0; i < beneficiaries.length; i++) {
            result[i] = beneficiaries[i];
        }
        return result;
    }

    /// @notice Checks if an address is a beneficiary
    /// @param account The address to check
    /// @return True if the address is a beneficiary
    function isBeneficiary(address account) public view returns (bool) {
        for (uint256 i = 0; i < beneficiaries.length; i++) {
            if (beneficiaries[i] == account) {
                return true;
            }
        }
        return false;
    }

    /// @notice Returns the address of the smart account that this will manages
    /// @return The smart account address
    function getSmartAccount() public view returns (address) {
        return smartAccount;
    }
}
