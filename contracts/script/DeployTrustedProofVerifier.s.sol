// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import "../src/TrustedProofVerifier.sol";

contract DeployTrustedProofVerifierScript is Script {
    function run() external {
        vm.startBroadcast();

        TrustedProofVerifier verifier = new TrustedProofVerifier();

        vm.stopBroadcast();

        console2.log("TrustedProofVerifier deployed at:", address(verifier));
        console2.log("Trusted signer (derived from pubkey):", verifier.trustedSignerAddress());
        console2.log("Trusted pubkey X:");
        console2.logBytes32(verifier.TRUSTED_PUBKEY_X());
        console2.log("Trusted pubkey Y:");
        console2.logBytes32(verifier.TRUSTED_PUBKEY_Y());
    }
}
