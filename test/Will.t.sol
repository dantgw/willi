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

import {Test, console} from "forge-std/Test.sol";
import {Will} from "../src/Will.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockModularAccount} from "./mocks/MockModularAccount.sol";

contract WillTest is Test {
    Will public will;
    MockModularAccount public modularAccount;
    MockERC20 public token;
    
    address public owner;
    address public beneficiary;
    uint256 public constant INITIAL_BALANCE = 100 ether;
    uint256 public constant INITIAL_TOKENS = 1000e18;
    uint256 public constant PROOF_OF_LIFE_PERIOD = 365 days;

    event SmartAccountSet(address indexed smartAccount);
    event FundsWithdrawn(address indexed to, uint256 amount);
    event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);

    function setUp() public {
        // Setup accounts
        owner = makeAddr("owner");
        beneficiary = makeAddr("beneficiary");
        
        // Deploy contracts
        vm.startPrank(owner);
        modularAccount = new MockModularAccount(address(will));
        
        // Deploy will with constructor arguments
        will = new Will(address(modularAccount));
        
        token = new MockERC20("Test Token", "TEST");
        
        // Fund modular account
        vm.deal(address(modularAccount), INITIAL_BALANCE);
        token.mint(address(modularAccount), INITIAL_TOKENS);
        vm.stopPrank();
    }

    function test_setup() public {
        assertTrue(modularAccount.isOwner(address(will)));
        assertEq(will.owner(), owner);
        assertEq(will.smartAccount(), address(modularAccount));
        assertEq(address(modularAccount).balance, INITIAL_BALANCE);
        assertEq(token.balanceOf(address(modularAccount)), INITIAL_TOKENS);
    }

    function test_ProofOfLife_ResetsPeriod() public {
        // Setup beneficiary
        address[] memory beneficiaries = new address[](1);
        beneficiaries[0] = beneficiary;
        
        vm.startPrank(owner);
        will.setBeneficiaries(beneficiaries);
        
        // Fast forward halfway through period
        vm.warp(block.timestamp + will.proofOfLifePeriod() / 2);
        
        // Prove life
        will.alive();
        
        // Try to withdraw just after old deadline (should fail)
        vm.warp(block.timestamp + will.proofOfLifePeriod() / 2 + 1);
        vm.stopPrank();

        vm.expectRevert("Will: owner is still active");
        vm.prank(beneficiary);
        will.claimAccount();
    }

    function test_cannotClaimAccountBeforeDead() public {
        address[] memory beneficiaries = new address[](1);
        beneficiaries[0] = beneficiary;
        
        vm.startPrank(owner);
        will.setBeneficiaries(beneficiaries);
        vm.stopPrank();

        // Try to claim before proof of life period expires
        vm.prank(beneficiary);
        vm.expectRevert("Will: owner is still active");
        will.claimAccount();
    }

    function test_claimAccountAfterDead() public {
        address[] memory beneficiaries = new address[](1);
        beneficiaries[0] = beneficiary;
        
        vm.startPrank(owner);
        will.setBeneficiaries(beneficiaries);
        
        // Fast forward past proof of life period
        vm.warp(block.timestamp + will.proofOfLifePeriod() + 1);
        vm.stopPrank();

        // Claim account
        vm.prank(beneficiary);
        will.claimAccount();

        // Verify ownership was transferred
        assertTrue(modularAccount.isOwner(beneficiary));
        assertFalse(modularAccount.isOwner(address(will)));
    }

    function test_cannotClaimAccountWithoutBeneficiaries() public {
        // Fast forward past proof of life period
        vm.warp(block.timestamp + will.proofOfLifePeriod() + 1);

        // Try to claim without beneficiaries set
        vm.prank(beneficiary);
        vm.expectRevert("Will: caller is not a beneficiary");
        will.claimAccount();
    }

    function test_cannotClaimAccountIfNotBeneficiary() public {
        address[] memory beneficiaries = new address[](1);
        beneficiaries[0] = makeAddr("other_beneficiary"); // Different from beneficiary
        
        vm.startPrank(owner);
        will.setBeneficiaries(beneficiaries);
        
        // Fast forward past proof of life period
        vm.warp(block.timestamp + will.proofOfLifePeriod() + 1);
        vm.stopPrank();

        // Try to claim without being a beneficiary
        vm.prank(beneficiary);
        vm.expectRevert("Will: caller is not a beneficiary");
        will.claimAccount();
    }


    function test_setBeneficiaries_RejectsZeroAddress() public {
        address[] memory beneficiaries = new address[](1);
        beneficiaries[0] = address(0);
        
        vm.startPrank(owner);
        vm.expectRevert("Will: invalid beneficiary address");
        will.setBeneficiaries(beneficiaries);
        vm.stopPrank();
    }

    function test_multipleOwnersClaim() public {
        address beneficiary2 = makeAddr("beneficiary2");
        
        address[] memory beneficiaries = new address[](2);
        beneficiaries[0] = beneficiary;
        beneficiaries[1] = beneficiary2;
        
        vm.startPrank(owner);
        will.setBeneficiaries(beneficiaries);
        
        // Fast forward past proof of life period
        vm.warp(block.timestamp + will.proofOfLifePeriod() + 1);
        vm.stopPrank();

        // Claim account
        vm.prank(beneficiary);
        will.claimAccount();

        // Verify ownership was transferred to both beneficiaries
        assertTrue(modularAccount.isOwner(beneficiary));
        assertTrue(modularAccount.isOwner(beneficiary2));
        assertFalse(modularAccount.isOwner(address(will)));
    }

    function test_constructorArguments() public {
        address testSmartAccount = makeAddr("testSmartAccount");

        Will newWill = new Will(testSmartAccount);

        assertEq(newWill.getSmartAccount(), testSmartAccount);
        assertEq(newWill.proofOfLifePeriod(), 90 days);
        assertEq(newWill.getBeneficiaries().length, 0);
    }

    function test_constructorRejectsZeroAddress() public {
        address[] memory testBeneficiaries = new address[](0);
        
        vm.expectRevert("Will: invalid smart account address");
        new Will(
            address(0)
        );
    }

}
