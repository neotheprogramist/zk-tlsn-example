// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./MerkleTreeLibrary.sol";
import {Poseidon2} from "poseidon2-M31-solidity/src/Poseidon2.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract PrivacyPool {
    using MerkleTreeLib for MerkleTreeLib.Tree;

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
    event VerifierUpdated(address indexed verifier);
    event RootRegisteredForTesting(uint256 indexed root);

    // Errors
    error TransferFailed();
    error NullifierAlreadyUsed();
    error InvalidRoot();
    error NotOwner();
    error VerifierNotSet();
    error InvalidVerifier();
    error VerifierCallFailed();
    error InvalidVerifierResponse();
    error ProofVerificationFailed();

    constructor(address _owner) {
        owner = _owner;
        tree.initialize();
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Set STWO verifier contract address
    function setVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) revert InvalidVerifier();
        stwoVerifier = verifier;
        emit VerifierUpdated(verifier);
    }

    /// @notice Testing helper: registers a root as valid in pool state.
    /// @dev Keep for e2e/dev only; remove in production deployment.
    function registerRootForTesting(uint256 root) external onlyOwner {
        tree.registerKnownRoot(root);
        emit RootRegisteredForTesting(root);
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
        (bool callSuccess, bytes memory returndata) = stwoVerifier.call(verifyCalldata);
        if (!callSuccess) revert VerifierCallFailed();
        if (returndata.length != 32) revert InvalidVerifierResponse();
        bool isValid = abi.decode(returndata, (bool));
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