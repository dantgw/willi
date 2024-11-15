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
        bool isBeneficiary = false;
        for (uint256 i = 0; i < beneficiaries.length; i++) {
            if (beneficiaries[i] == msg.sender) {
                isBeneficiary = true;
                break;
            }
        }
        require(isBeneficiary, "Will: caller is not a beneficiary");
        _;
    }

    modifier onlyAfterDead() {
        require(block.timestamp > lastActiveTime + proofOfLifePeriod, "Will: owner is still active");
        _;
    }

    constructor() Ownable() {
        lastActiveTime = block.timestamp;
        proofOfLifePeriod = 365 days;
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

        // Call the smart account's changeOwners function
        (bool success, bytes memory data) = smartAccount.call(
            abi.encodeWithSignature("updateOwners(address[], address[])", beneficiaries, new address[](0))
        );
        
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
}
