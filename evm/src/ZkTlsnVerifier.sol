// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {HonkVerifier} from "./generated/HonkVerifier.sol";

contract ZkTlsnVerifier {
    error InvalidProof();
    error NotVerified();

    event ProofAccepted(address indexed account);

    HonkVerifier public immutable VERIFIER;
    mapping(address => bool) public verified;

    constructor(address verifier_) {
        VERIFIER = HonkVerifier(verifier_);
    }

    function submitProof(bytes calldata proof, bytes32[] calldata publicInputs) external {
        (bool success, bytes memory returndata) =
            address(VERIFIER).staticcall(abi.encodeCall(VERIFIER.verify, (proof, publicInputs)));
        if (!success || !abi.decode(returndata, (bool))) {
            revert InvalidProof();
        }

        verified[msg.sender] = true;
        emit ProofAccepted(msg.sender);
    }

    function gatedAction() external view returns (bool allowed) {
        if (!verified[msg.sender]) {
            revert NotVerified();
        }

        return true;
    }
}
