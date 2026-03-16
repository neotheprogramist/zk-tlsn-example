// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {HonkVerifier} from "./generated/HonkVerifier.sol";
import {StableToken} from "./StableToken.sol";

contract StableMintGate {
    error InvalidProof();
    error WrongFiatDestination(uint256 expectedToUserId, uint256 actualToUserId);
    error TxAlreadyClaimed(uint256 txId);

    event MintClaimed(address indexed account, address indexed recipient, uint256 indexed txId, uint256 amount);

    uint256 public constant TX_ID_INDEX = 32;
    uint256 public constant TO_USER_ID_INDEX = 33;
    uint256 public constant AMOUNT_INDEX = 34;
    uint256 public constant TOKEN_UNIT = 1e18;

    HonkVerifier public immutable VERIFIER;
    StableToken public immutable TOKEN;
    uint256 public immutable EXPECTED_TO_USER_ID;
    mapping(uint256 txId => bool claimed) public claimedTxId;

    constructor(address verifier_, address token_, uint256 expectedToUserId_) {
        VERIFIER = HonkVerifier(verifier_);
        TOKEN = StableToken(token_);
        EXPECTED_TO_USER_ID = expectedToUserId_;
    }

    function proveAndMint(bytes calldata proof, bytes32[] calldata publicInputs, address recipient) external {
        uint256 txId = uint256(publicInputs[TX_ID_INDEX]);
        uint256 toUserId = uint256(publicInputs[TO_USER_ID_INDEX]);
        uint256 amount = uint256(publicInputs[AMOUNT_INDEX]);

        if (toUserId != EXPECTED_TO_USER_ID) {
            revert WrongFiatDestination(EXPECTED_TO_USER_ID, toUserId);
        }
        if (claimedTxId[txId]) {
            revert TxAlreadyClaimed(txId);
        }

        (bool success, bytes memory returndata) =
            address(VERIFIER).staticcall(abi.encodeCall(VERIFIER.verify, (proof, publicInputs)));
        if (!success || !abi.decode(returndata, (bool))) {
            revert InvalidProof();
        }

        claimedTxId[txId] = true;
        TOKEN.mint(recipient, amount * TOKEN_UNIT);
        emit MintClaimed(msg.sender, recipient, txId, amount);
    }
}
