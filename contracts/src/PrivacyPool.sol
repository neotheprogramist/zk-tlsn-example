// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./MerkleTreeLibrary.sol";
import {Poseidon2} from "poseidon2-M31-solidity/src/Poseidon2.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

enum OfferStatus {
    CREATED,
    CANCELLED
}

struct Offer {
    uint256 secretHash;
    string offerType;
    string currency;
    uint256 cryptoAmount;
    uint256 fiatAmount; // 0 for dynamic offers
    address tokenAddress;
    OfferStatus status;
    string revTag;
    uint256 timestamp;
    uint256 cancelHash;
}


contract PrivacyPool {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    mapping(uint256 => Offer) public offers; // secretHash => Offer
    uint256[] public activeOffers; // Array of active offer secretHashes for enumeration

    // Storage
    MerkleTreeLib.Tree private tree;
    mapping(uint256 => bool) public nullifierHashes;
    address public owner;
    address public stwoVerifier;

    // Events
    event Deposit(
        uint256 indexed commitment,
        uint256 amount,
        address indexed token,
        uint64 leafIndex,
        uint256 newRoot
    );
    event Withdraw(uint256 indexed nullifier, address indexed recipient, address token, uint256 amount);
    event VerificationGasUsed(uint256 gasUsed, bool isValid);
    event VerifierUpdated(address indexed verifier);
    event RootRegisteredForTesting(uint256 indexed root);
    event OfferCreated(
        uint256 indexed secretHash,
        string indexed offerType,
        uint256 cryptoAmount,
        uint256 fiatAmount,
        string currency,
        address tokenAddress,
        string revTag
    );
    event OfferCancelled(uint256 indexed secretHash, uint256 cancelHash);
    event OfferClaimed(uint256 indexed secretHash, uint256 refundAmount);

    // Errors
    error TransferFailed();
    error NullifierAlreadyUsed();
    error InvalidRoot();
    error OfferNotFound();
    error OfferAlreadyExists();
    error OfferNotActive();
    error VerifierNotSet();
    error InvalidVerifier();
    error VerifierCallFailed();
    error InvalidVerifierResponse();
    error ProofVerificationFailed();

    constructor(
        address _owner,
        address _stwoVerifier
    ) {
        owner = _owner;
        stwoVerifier = _stwoVerifier;
        tree.initialize();
    }

    /// @notice Hash two values using Poseidon2
    function poseidonHash(uint256 left, uint256 right) public pure returns (uint256) {
        return Poseidon2.hashTwo(left, right);
    }

    /// @notice Internal hash function
    function _poseidonHash(uint256 left, uint256 right) internal pure returns (uint256) {
        return Poseidon2.hashTwo(left, right);
    }

    /// @notice Computes the commitment inserted into the Merkle tree for a deposit.
    function computeCommitment(
        uint256 secretNullifierHash,
        uint256 amount,
        address token
    ) public pure returns (uint256) {
        uint256 secretNullifierAmountHash = _poseidonHash(secretNullifierHash, amount);
        return _poseidonHash(secretNullifierAmountHash, uint256(uint160(token)));
    }

    /// @notice Deposit tokens into the privacy pool
    function deposit(
        uint256 secretNullifierHash,
        uint256 amount,
        address token
    ) external {
        uint64 leafIndex = tree.freeLeafIndex;
        uint256 commitment = computeCommitment(secretNullifierHash, amount, token);

        IERC20 erc20 = IERC20(token);
        bool success = erc20.transferFrom(msg.sender, address(this), amount);
        if (!success) revert TransferFailed();

        // Add commitment to merkle tree
        uint256 newRoot = tree.addLeaf(commitment);
        emit Deposit(commitment, amount, token, leafIndex, newRoot);
    }

    /// @notice Withdraw tokens from the privacy pool with in-contract proof verification
    function withdraw(
        uint256 root,
        uint256 nullifier,
        address token,
        uint256 amount,
        address recipient,
        uint256 refundCommitmentHash,
        bytes calldata verifyCalldata
    ) external {
        // Check if nullifier already used
        if (nullifierHashes[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle root is valid
        if (!tree.isValidRoot(root)) {
            revert InvalidRoot();
        }

        if (stwoVerifier == address(0)) revert VerifierNotSet();

        // Verify STWO proof atomically in the same transaction.
        // STWOVerifier.verify() is non-view and updates internal state, so staticcall reverts.
        uint256 gasBeforeVerification = gasleft();
        (bool callSuccess, bytes memory returndata) = stwoVerifier.call(verifyCalldata);
        uint256 verificationGasUsed = gasBeforeVerification - gasleft();
        if (!callSuccess) revert VerifierCallFailed();
        if (returndata.length != 32) revert InvalidVerifierResponse();
        bool isValid = abi.decode(returndata, (bool));
        emit VerificationGasUsed(verificationGasUsed, isValid);
        if (!isValid) revert ProofVerificationFailed();

        // Mark nullifier as used
        nullifierHashes[nullifier] = true;

        // For partial withdrawals, insert the change/refund commitment as a new leaf.
        if (refundCommitmentHash != 0) {
            tree.addLeaf(refundCommitmentHash);
        }

        // Transfer tokens to recipient
        IERC20 erc20 = IERC20(token);
        bool success = erc20.transfer(recipient, amount);
        if (!success) revert TransferFailed();

        emit Withdraw(nullifier, recipient, token, amount);
    }

    // Paymoney offer Functions
    function createOffer(
        uint256 root,
        uint256 nullifier,
        address token,
        uint256 amount,
        uint256 refundCommitmentHash,
        uint256 secretHash,
        string calldata currency,
        uint256 fiatAmount,
        string calldata revTag,
        bytes calldata verifyCalldata
    ) external {
        // Check if nullifier already used
        if (nullifierHashes[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle root is valid
        if (!tree.isValidRoot(root)) {
            revert InvalidRoot();
        }

        if (stwoVerifier == address(0)) revert VerifierNotSet();

        // Verify proof
        uint256 gasBeforeVerification = gasleft();
        (bool callSuccess, bytes memory returndata) = stwoVerifier.call(verifyCalldata);
        uint256 verificationGasUsed = gasBeforeVerification - gasleft();
        if (!callSuccess) revert VerifierCallFailed();
        if (returndata.length != 32) revert InvalidVerifierResponse();
        bool isValid = abi.decode(returndata, (bool));
        emit VerificationGasUsed(verificationGasUsed, isValid);
        if (!isValid) revert ProofVerificationFailed();

        // Check if offer already exists
        if (offers[secretHash].timestamp != 0) {
            revert OfferAlreadyExists();
        }

        // Mark nullifier as used
        nullifierHashes[nullifier] = true;

        // Add refund commitment to tree
        tree.addLeaf(refundCommitmentHash);

        // Determine offer type based on fiatAmount
        string memory offerType = fiatAmount > 0 ? "static" : "dynamic";

        // Store offer
        offers[secretHash] = Offer({
            secretHash: secretHash,
            offerType: offerType,
            currency: currency,
            cryptoAmount: amount,
            fiatAmount: fiatAmount,
            tokenAddress: token,
            status: OfferStatus.CREATED,
            revTag: revTag,
            timestamp: block.timestamp,
            cancelHash: 0
        });

        // Add to active offers array
        activeOffers.push(secretHash);

        // Emit event
        emit OfferCreated(
            secretHash,
            offerType,
            amount,
            fiatAmount,
            currency,
            token,
            revTag
        );
    }

    /// @notice Cancel an offer with proof verification
    function cancelOffer(
        uint256 root,
        uint256 nullifier,
        address token,
        uint256 amount,
        uint256 refundCommitmentHash,
        uint256 secretHash,
        uint256 cancelHash,
        bytes calldata verifyCalldata
    ) external {
        // Check if offer exists and is active
        if (offers[secretHash].timestamp == 0) {
            revert OfferNotFound();
        }
        if (offers[secretHash].status != OfferStatus.CREATED) {
            revert OfferNotActive();
        }

        // Validate that token matches offer
        require(token == offers[secretHash].tokenAddress, "Token mismatch");
        require(amount == offers[secretHash].cryptoAmount, "Amount mismatch");

        // Check if nullifier already used
        if (nullifierHashes[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle root is valid
        if (!tree.isValidRoot(root)) {
            revert InvalidRoot();
        }

        if (stwoVerifier == address(0)) revert VerifierNotSet();

        // Verify proof
        uint256 gasBeforeVerification = gasleft();
        (bool callSuccess, bytes memory returndata) = stwoVerifier.call(verifyCalldata);
        uint256 verificationGasUsed = gasBeforeVerification - gasleft();
        if (!callSuccess) revert VerifierCallFailed();
        if (returndata.length != 32) revert InvalidVerifierResponse();
        bool isValid = abi.decode(returndata, (bool));
        emit VerificationGasUsed(verificationGasUsed, isValid);
        if (!isValid) revert ProofVerificationFailed();

        // Mark nullifier as used
        nullifierHashes[nullifier] = true;

        // Add refund commitment to tree
        tree.addLeaf(refundCommitmentHash);

        // Mark offer as cancelled
        offers[secretHash].status = OfferStatus.CANCELLED;
        offers[secretHash].cancelHash = cancelHash;

        // Remove from active offers
        for (uint256 i = 0; i < activeOffers.length; i++) {
            if (activeOffers[i] == secretHash) {
                activeOffers[i] = activeOffers[activeOffers.length - 1];
                activeOffers.pop();
                break;
            }
        }

        emit OfferCancelled(secretHash, cancelHash);
    }

    /// @notice Claim refund from a cancelled offer
    function cancelClaim(
        uint256 root,
        uint256 nullifier,
        address token,
        uint256 amount,
        uint256 refundCommitmentHash,
        uint256 secretHash,
        bytes calldata verifyCalldata
    ) external {
        // Check if offer exists and is cancelled
        if (offers[secretHash].timestamp == 0) {
            revert OfferNotFound();
        }
        if (offers[secretHash].status != OfferStatus.CANCELLED) {
            revert OfferNotActive();
        }

        // Validate that token matches offer
        require(token == offers[secretHash].tokenAddress, "Token mismatch");
        require(amount <= offers[secretHash].cryptoAmount, "Amount exceeds offer");

        // Check if nullifier already used
        if (nullifierHashes[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle root is valid
        if (!tree.isValidRoot(root)) {
            revert InvalidRoot();
        }

        if (stwoVerifier == address(0)) revert VerifierNotSet();

        // Verify proof
        uint256 gasBeforeVerification = gasleft();
        (bool callSuccess, bytes memory returndata) = stwoVerifier.call(verifyCalldata);
        uint256 verificationGasUsed = gasBeforeVerification - gasleft();
        if (!callSuccess) revert VerifierCallFailed();
        if (returndata.length != 32) revert InvalidVerifierResponse();
        bool isValid = abi.decode(returndata, (bool));
        emit VerificationGasUsed(verificationGasUsed, isValid);
        if (!isValid) revert ProofVerificationFailed();

        // Mark nullifier as used
        nullifierHashes[nullifier] = true;

        // Add refund commitment to tree
        tree.addLeaf(refundCommitmentHash);

        emit OfferClaimed(secretHash, amount);
    }

    /// @notice Get current merkle root
    function getCurrentRoot() external view returns (uint256) {
        return tree.currentRoot;
    }

    /// @notice Check if a root is valid
    function isValidRoot(uint256 root) external view returns (bool) {
        return tree.isValidRoot(root);
    }

    /// @notice Check if nullifier was used
    function isNullifierUsed(uint256 nullifier) external view returns (bool) {
        return nullifierHashes[nullifier];
    }

    /// @notice Returns the next leaf index where a new deposit will be inserted.
    function getNextLeafIndex() external view returns (uint64) {
        return tree.freeLeafIndex;
    }

    /// @notice Returns the empty-tree zero hash for a given level.
    function getZeroHash(uint256 level) external view returns (uint256) {
        return tree.getZeroHash(level);
    }

    /// @notice Returns the current left-path value for a given level.
    function getLeftPath(uint256 level) external view returns (uint256) {
        return tree.getLeftPath(level);
    }
}
