// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {StableToken} from "./StableToken.sol";

interface ISettlementVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

contract SettlementMintGate {
    error InvalidProof();
    error WrongFiatDestination(uint256 expectedToUserId, uint256 actualToUserId);
    error RootAlreadyClaimed(bytes32 transfersRoot);
    error InvalidVkHashes(
        bytes32 expectedNullVkHash,
        bytes32 actualNullVkHash,
        bytes32 expectedRecursiveVkHash,
        bytes32 actualRecursiveVkHash,
        bytes32 expectedInnerVkHash,
        bytes32 actualInnerVkHash
    );

    event SettlementClaimed(
        address indexed sender, address indexed recipient, bytes32 indexed transfersRoot, uint256 totalAmount
    );

    uint256 public constant RESERVED_INDEX = 0;
    uint256 public constant TOTAL_AMOUNT_INDEX = 1;
    uint256 public constant TRANSFERS_ROOT_INDEX = 2;
    uint256 public constant TO_USER_ID_INDEX = 3;
    uint256 public constant NULL_VK_HASH_INDEX = 4;
    uint256 public constant RECURSIVE_VK_HASH_INDEX = 5;
    uint256 public constant INNER_VK_HASH_INDEX = 6;
    uint256 public constant TOKEN_UNIT = 1e18;

    ISettlementVerifier public immutable VERIFIER;
    StableToken public immutable TOKEN;
    uint256 public immutable EXPECTED_TO_USER_ID;
    bytes32 public immutable EXPECTED_NULL_VK_HASH;
    bytes32 public immutable EXPECTED_RECURSIVE_VK_HASH;
    bytes32 public immutable EXPECTED_INNER_VK_HASH;
    mapping(bytes32 transfersRoot => bool claimed) public claimedRoot;

    constructor(
        address verifier_,
        address token_,
        uint256 expectedToUserId_,
        bytes32 expectedNullVkHash_,
        bytes32 expectedRecursiveVkHash_,
        bytes32 expectedInnerVkHash_
    ) {
        VERIFIER = ISettlementVerifier(verifier_);
        TOKEN = StableToken(token_);
        EXPECTED_TO_USER_ID = expectedToUserId_;
        EXPECTED_NULL_VK_HASH = expectedNullVkHash_;
        EXPECTED_RECURSIVE_VK_HASH = expectedRecursiveVkHash_;
        EXPECTED_INNER_VK_HASH = expectedInnerVkHash_;
    }

    function settle(bytes calldata proof, bytes32[] calldata publicInputs, address recipient) external {
        uint256 totalAmount = uint256(publicInputs[TOTAL_AMOUNT_INDEX]);
        bytes32 transfersRoot = publicInputs[TRANSFERS_ROOT_INDEX];
        uint256 toUserId = uint256(publicInputs[TO_USER_ID_INDEX]);
        bytes32 nullVkHash = publicInputs[NULL_VK_HASH_INDEX];
        bytes32 recursiveVkHash = publicInputs[RECURSIVE_VK_HASH_INDEX];
        bytes32 innerVkHash = publicInputs[INNER_VK_HASH_INDEX];

        if (toUserId != EXPECTED_TO_USER_ID) {
            revert WrongFiatDestination(EXPECTED_TO_USER_ID, toUserId);
        }
        if (nullVkHash != EXPECTED_NULL_VK_HASH || recursiveVkHash != EXPECTED_RECURSIVE_VK_HASH || innerVkHash != EXPECTED_INNER_VK_HASH) {
            revert InvalidVkHashes(EXPECTED_NULL_VK_HASH, nullVkHash, EXPECTED_RECURSIVE_VK_HASH, recursiveVkHash, EXPECTED_INNER_VK_HASH, innerVkHash);
        }
        if (claimedRoot[transfersRoot]) {
            revert RootAlreadyClaimed(transfersRoot);
        }

        (bool success, bytes memory returndata) =
            address(VERIFIER).staticcall(abi.encodeCall(VERIFIER.verify, (proof, publicInputs)));
        if (!success || !abi.decode(returndata, (bool))) {
            revert InvalidProof();
        }

        claimedRoot[transfersRoot] = true;
        TOKEN.mint(recipient, totalAmount * TOKEN_UNIT);
        emit SettlementClaimed(msg.sender, recipient, transfersRoot, totalAmount);
    }
}
