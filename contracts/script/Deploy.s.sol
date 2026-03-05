// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/PrivacyPool.sol";
import "../src/MockERC20.sol";

contract DeployScript is Script {
    function run() external {
        vm.startBroadcast();
        
        // Deploy PrivacyPool
        PrivacyPool pool = new PrivacyPool(msg.sender);
        console.log("PrivacyPool deployed at:", address(pool));
        
        // Deploy MockERC20 for testing (1 million tokens with 6 decimals)
        MockERC20 mockToken = new MockERC20("Mock USDC", "mUSDC", 1_000_000 * 10**6);
        console.log("MockERC20 deployed at:", address(mockToken));
        
        // Get initial root
        uint256 root = pool.getCurrentRoot();
        console.log("Initial Merkle root:", root);
        
        vm.stopBroadcast();
        
        console.log("\n=== Deployment Summary ===");
        console.log("PrivacyPool:", address(pool));
        console.log("MockERC20:", address(mockToken));
        console.log("Owner:", msg.sender);
        console.log("Initial Root:", root);
    }
}