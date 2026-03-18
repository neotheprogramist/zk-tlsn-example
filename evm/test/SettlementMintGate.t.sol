// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {SettlementMintGate} from "../src/SettlementMintGate.sol";
import {SettlementHonkVerifier} from "../src/generated/SettlementHonkVerifier.sol";
import {StableToken} from "../src/StableToken.sol";

contract SettlementMintGateTest is Test {
    string internal constant PROOF_PATH = "evm/testdata/settlement_proof.bin";
    string internal constant PUBLIC_INPUTS_PATH = "evm/testdata/settlement_public_inputs.bin";
    uint256 internal constant RESERVED_INDEX = 0;
    uint256 internal constant TOTAL_AMOUNT_INDEX = 1;
    uint256 internal constant TRANSFERS_ROOT_INDEX = 2;
    uint256 internal constant TO_USER_ID_INDEX = 3;
    uint256 internal constant NULL_VK_HASH_INDEX = 4;
    uint256 internal constant RECURSIVE_VK_HASH_INDEX = 5;
    uint256 internal constant INNER_VK_HASH_INDEX = 6;

    SettlementHonkVerifier internal verifier;
    StableToken internal token;
    SettlementMintGate internal gate;

    function setUp() public {
        bytes32[] memory publicInputs = loadPublicInputs();

        verifier = new SettlementHonkVerifier();
        token = new StableToken(address(this));
        gate = new SettlementMintGate(
            address(verifier),
            address(token),
            uint256(publicInputs[TO_USER_ID_INDEX]),
            publicInputs[NULL_VK_HASH_INDEX],
            publicInputs[RECURSIVE_VK_HASH_INDEX],
            publicInputs[INNER_VK_HASH_INDEX]
        );
        token.transferOwnership(address(gate));
    }

    function test_settle_mintsFixtureAmount() public {
        address recipient = makeAddr("recipient");
        bytes32[] memory publicInputs = loadPublicInputs();

        assertFalse(gate.claimedRoot(publicInputs[TRANSFERS_ROOT_INDEX]));
        gate.settle(loadProof(), publicInputs, recipient);

        assertTrue(gate.claimedRoot(publicInputs[TRANSFERS_ROOT_INDEX]));
        assertEq(token.balanceOf(recipient), uint256(publicInputs[TOTAL_AMOUNT_INDEX]) * 1 ether);
        assertEq(token.owner(), address(gate));
    }

    function test_settle_revertsOnReplay() public {
        bytes32[] memory publicInputs = loadPublicInputs();

        gate.settle(loadProof(), publicInputs, makeAddr("firstRecipient"));

        vm.expectRevert(
            abi.encodeWithSelector(SettlementMintGate.RootAlreadyClaimed.selector, publicInputs[TRANSFERS_ROOT_INDEX])
        );
        gate.settle(loadProof(), publicInputs, makeAddr("secondRecipient"));
    }

    function test_settle_revertsOnWrongFiatDestination() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        publicInputs[TO_USER_ID_INDEX] = bytes32(uint256(2));

        vm.expectRevert(
            abi.encodeWithSelector(
                SettlementMintGate.WrongFiatDestination.selector,
                uint256(loadPublicInputs()[TO_USER_ID_INDEX]),
                uint256(2)
            )
        );
        gate.settle(loadProof(), publicInputs, address(this));
    }

    function test_settle_revertsOnInvalidVkHashes() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        bytes32 originalNull = publicInputs[NULL_VK_HASH_INDEX];
        bytes32 originalRecursive = publicInputs[RECURSIVE_VK_HASH_INDEX];
        bytes32 originalInner = publicInputs[INNER_VK_HASH_INDEX];
        publicInputs[NULL_VK_HASH_INDEX] = bytes32(uint256(0xdead));

        vm.expectRevert(
            abi.encodeWithSelector(
                SettlementMintGate.InvalidVkHashes.selector,
                originalNull,
                bytes32(uint256(0xdead)),
                originalRecursive,
                originalRecursive,
                originalInner,
                originalInner
            )
        );
        gate.settle(loadProof(), publicInputs, address(this));
    }

    function test_settle_revertsOnTamperedProof() public {
        bytes memory proof = loadProof();
        bytes32[] memory publicInputs = loadPublicInputs();
        address recipient = makeAddr("recipient");
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 0x01);

        vm.expectRevert(SettlementMintGate.InvalidProof.selector);
        gate.settle(proof, publicInputs, recipient);

        assertFalse(gate.claimedRoot(publicInputs[TRANSFERS_ROOT_INDEX]));
        assertEq(token.balanceOf(recipient), 0);
        assertEq(token.owner(), address(gate));
    }

    function test_settle_revertsOnTamperedPublicInputs() public {
        bytes32[] memory publicInputs = loadPublicInputs();
        address recipient = makeAddr("recipient");
        publicInputs[TOTAL_AMOUNT_INDEX] = bytes32(uint256(publicInputs[TOTAL_AMOUNT_INDEX]) ^ 0x01);

        vm.expectRevert(SettlementMintGate.InvalidProof.selector);
        gate.settle(loadProof(), publicInputs, recipient);

        assertFalse(gate.claimedRoot(loadPublicInputs()[TRANSFERS_ROOT_INDEX]));
        assertEq(token.balanceOf(recipient), 0);
        assertEq(token.owner(), address(gate));
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
