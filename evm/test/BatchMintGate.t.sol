// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {BatchMintGate} from "../src/BatchMintGate.sol";
import {RecursiveHonkVerifier} from "../src/generated/RecursiveHonkVerifier.sol";
import {StableToken} from "../src/StableToken.sol";

contract BatchMintGateTest is Test {
    string internal constant PROOF_PATH = "evm/testdata/batch_proof.bin";
    string internal constant PUBLIC_INPUTS_PATH = "evm/testdata/batch_public_inputs.bin";
    uint256 internal constant TOTAL_AMOUNT_INDEX = 1;
    uint256 internal constant TRANSFERS_ROOT_INDEX = 2;
    uint256 internal constant TO_USER_ID_INDEX = 3;
    uint256 internal constant NULL_VK_HASH_INDEX = 4;
    uint256 internal constant RECURSIVE_VK_HASH_INDEX = 5;

    RecursiveHonkVerifier internal verifier;
    StableToken internal token;
    BatchMintGate internal gate;

    function setUp() public {
        bytes32[] memory publicInputs = loadPublicInputs();

        verifier = new RecursiveHonkVerifier();
        token = new StableToken(address(this));
        gate = new BatchMintGate(
            address(verifier),
            address(token),
            uint256(publicInputs[TO_USER_ID_INDEX]),
            publicInputs[NULL_VK_HASH_INDEX],
            publicInputs[RECURSIVE_VK_HASH_INDEX]
        );
        token.transferOwnership(address(gate));
    }

    function test_batchMint_mintsFixtureAmount() public {
        address recipient = makeAddr("recipient");
        bytes32[] memory publicInputs = loadPublicInputs();

        gate.batchMint(loadProof(), publicInputs, recipient);

        assertTrue(gate.claimedRoot(publicInputs[TRANSFERS_ROOT_INDEX]));
        assertEq(token.balanceOf(recipient), uint256(publicInputs[TOTAL_AMOUNT_INDEX]) * 1 ether);
        assertEq(token.owner(), address(gate));
    }

    function test_batchMint_revertsOnReplay() public {
        bytes32[] memory publicInputs = loadPublicInputs();

        gate.batchMint(loadProof(), publicInputs, address(this));

        vm.expectRevert(
            abi.encodeWithSelector(BatchMintGate.RootAlreadyClaimed.selector, publicInputs[TRANSFERS_ROOT_INDEX])
        );
        gate.batchMint(loadProof(), publicInputs, address(this));
    }

    function test_batchMint_revertsOnWrongFiatDestination() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[TO_USER_ID_INDEX] = bytes32(uint256(2));

        vm.expectRevert(
            abi.encodeWithSelector(
                BatchMintGate.WrongFiatDestination.selector, uint256(loadPublicInputs()[TO_USER_ID_INDEX]), uint256(2)
            )
        );
        gate.batchMint(loadProof(), publicInputs, address(this));
    }

    function test_batchMint_revertsOnWrongVkHashes() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[NULL_VK_HASH_INDEX] = bytes32(uint256(1));

        vm.expectRevert();
        gate.batchMint(loadProof(), publicInputs, address(this));
    }

    function test_batchMint_revertsOnTamperedProof() public {
        bytes memory proof = loadProof();
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 0x01);

        vm.expectRevert(BatchMintGate.InvalidProof.selector);
        gate.batchMint(proof, loadPublicInputs(), address(this));
    }

    function test_batchMint_revertsOnTamperedPublicInputs() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[TOTAL_AMOUNT_INDEX] = bytes32(uint256(publicInputs[0]) ^ 0x01);

        vm.expectRevert(BatchMintGate.InvalidProof.selector);
        gate.batchMint(loadProof(), publicInputs, address(this));
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
