// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./MerkleTreeLibrary.sol";
import {Poseidon2} from "poseidon2-M31-solidity/Poseidon2.sol";

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

    // Events
    event Deposit(uint256 indexed commitment, uint256 amount, address indexed token);
    event Withdraw(uint256 indexed nullifier, address indexed recipient, address token, uint256 amount);

    // Errors
    error TransferFailed();
    error NullifierAlreadyUsed();
    error InvalidRoot();

    constructor(address _owner) {
        owner = _owner;
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

    /// @notice Deposit tokens into the privacy pool
    function deposit(
        uint256 secretNullifierHash,
        uint256 amount,
        address token
    ) external {
        uint256 secretNullifierAmountHash = _poseidonHash(
            secretNullifierHash,
            amount
        );
        uint256 commitment = _poseidonHash(
            secretNullifierAmountHash,
            uint256(uint160(token))
        );

        IERC20 erc20 = IERC20(token);
        bool success = erc20.transferFrom(msg.sender, address(this), amount);
        if (!success) revert TransferFailed();

        // Add commitment to merkle tree
        tree.addLeaf(commitment);
        emit Deposit(secretNullifierHash, amount, token);
    }

    /// @notice Withdraw tokens from the privacy pool (without proof verification for now)
    function withdraw(
        uint256 root,
        uint256 nullifier,
        address token,
        uint256 amount,
        address recipient
    ) external {
        // Check if nullifier already used
        if (nullifierHashes[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle root is valid
        if (!tree.isValidRoot(root)) {
            revert InvalidRoot();
        }

        // Mark nullifier as used
        nullifierHashes[nullifier] = true;

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
}
