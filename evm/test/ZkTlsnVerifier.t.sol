// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {HonkVerifier} from "../src/generated/HonkVerifier.sol";
import {ZkTlsnVerifier} from "../src/ZkTlsnVerifier.sol";

contract ZkTlsnVerifierTest is Test {
    string internal constant PROOF_PATH = "evm/testdata/proof.bin";
    string internal constant PUBLIC_INPUTS_PATH = "evm/testdata/public_inputs.bin";

    HonkVerifier internal verifier;
    ZkTlsnVerifier internal gate;

    function setUp() public {
        verifier = new HonkVerifier();
        gate = new ZkTlsnVerifier(address(verifier));
    }

    function test_submitProof_acceptsFixture() public {
        gate.submitProof(loadProof(), loadPublicInputs());

        assertTrue(gate.verified(address(this)));
    }

    function test_gatedAction_revertsBeforeVerification() public {
        vm.expectRevert(ZkTlsnVerifier.NotVerified.selector);
        gate.gatedAction();
    }

    function test_gatedAction_succeedsAfterVerification() public {
        gate.submitProof(loadProof(), loadPublicInputs());

        assertTrue(gate.gatedAction());
    }

    function test_submitProof_revertsOnTamperedProof() public {
        bytes memory proof = loadProof();
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 0x01);

        vm.expectRevert(ZkTlsnVerifier.InvalidProof.selector);
        gate.submitProof(proof, loadPublicInputs());
    }

    function test_submitProof_revertsOnTamperedPublicInputs() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[0] = bytes32(uint256(publicInputs[0]) ^ 0x01);

        vm.expectRevert(ZkTlsnVerifier.InvalidProof.selector);
        gate.submitProof(loadProof(), publicInputs);
    }

    function loadProof() internal view returns (bytes memory) {
        return vm.readFileBinary(PROOF_PATH);
    }

    function loadPublicInputs() internal view returns (bytes32[] memory publicInputs) {
        bytes memory raw = vm.readFileBinary(PUBLIC_INPUTS_PATH);
        require(raw.length % 32 == 0, "invalid public input binary");

        publicInputs = new bytes32[](raw.length / 32);
        for (uint256 i = 0; i < publicInputs.length; i++) {
            bytes32 word;
            uint256 offset = 32 + (i * 32);
            assembly {
                word := mload(add(raw, offset))
            }
            publicInputs[i] = word;
        }
    }
}
