// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {HonkVerifier} from "../src/generated/HonkVerifier.sol";
import {StableMintGate} from "../src/StableMintGate.sol";
import {StableToken} from "../src/StableToken.sol";

contract StableMintGateTest is Test {
    string internal constant PROOF_PATH = "evm/testdata/proof.bin";
    string internal constant PUBLIC_INPUTS_PATH = "evm/testdata/public_inputs.bin";

    HonkVerifier internal verifier;
    StableToken internal token;
    StableMintGate internal gate;

    uint256 internal constant FIXTURE_TX_ID = 1;
    uint256 internal constant FIXTURE_TO_USER_ID = 3;
    uint256 internal constant FIXTURE_MINT_AMOUNT = 25 ether;

    function setUp() public {
        verifier = new HonkVerifier();
        token = new StableToken(address(this));
        gate = new StableMintGate(address(verifier), address(token), FIXTURE_TO_USER_ID);
        token.transferOwnership(address(gate));
    }

    function test_proveAndMint_mintsFixtureAmount() public {
        address recipient = makeAddr("recipient");

        gate.proveAndMint(loadProof(), loadPublicInputs(), recipient);

        assertTrue(gate.claimedTxId(FIXTURE_TX_ID));
        assertEq(token.balanceOf(recipient), FIXTURE_MINT_AMOUNT);
        assertEq(token.owner(), address(gate));
    }

    function test_proveAndMint_revertsOnReplay() public {
        gate.proveAndMint(loadProof(), loadPublicInputs(), address(this));

        vm.expectRevert(abi.encodeWithSelector(StableMintGate.TxAlreadyClaimed.selector, FIXTURE_TX_ID));
        gate.proveAndMint(loadProof(), loadPublicInputs(), address(this));
    }

    function test_proveAndMint_revertsOnWrongFiatDestination() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[gate.TO_USER_ID_INDEX()] = bytes32(uint256(2));

        vm.expectRevert(
            abi.encodeWithSelector(StableMintGate.WrongFiatDestination.selector, FIXTURE_TO_USER_ID, uint256(2))
        );
        gate.proveAndMint(loadProof(), publicInputs, address(this));
    }

    function test_proveAndMint_revertsOnTamperedProof() public {
        bytes memory proof = loadProof();
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 0x01);

        vm.expectRevert(StableMintGate.InvalidProof.selector);
        gate.proveAndMint(proof, loadPublicInputs(), address(this));
    }

    function test_proveAndMint_revertsOnTamperedPublicInputs() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[0] = bytes32(uint256(publicInputs[0]) ^ 0x01);

        vm.expectRevert(StableMintGate.InvalidProof.selector);
        gate.proveAndMint(loadProof(), publicInputs, address(this));
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
