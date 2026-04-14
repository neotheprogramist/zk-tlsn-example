// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Poseidon2} from "poseidon2-M31-solidity/src/Poseidon2.sol";

library IndexedNullifierTreeLib {
    struct Tree {
        uint256 currentRoot;
        uint64 nextInsertionIndex;
        mapping(uint256 => bool) roots;
        mapping(uint256 => bool) usedNullifiers;
    }

    error NullifierAlreadyUsed();
    error InvalidNullifierRoot();

    function initialize(Tree storage self) internal {
        self.currentRoot = emptyRoot();
        self.roots[self.currentRoot] = true;
        // Aztec-style indexed nullifier trees reserve index 0 for sentinel leaf.
        self.nextInsertionIndex = 1;
    }

    function consumeWithTransition(
        Tree storage self,
        uint256 nullifier,
        uint256 rootBefore,
        uint256 rootAfter
    ) internal {
        if (self.usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (rootBefore != self.currentRoot) {
            revert InvalidNullifierRoot();
        }

        self.usedNullifiers[nullifier] = true;
        self.currentRoot = rootAfter;
        self.roots[rootAfter] = true;
        self.nextInsertionIndex += 1;
    }

    // Compatibility helper for flows not yet emitting indexed nullifier root transition.
    function consumeUnchecked(Tree storage self, uint256 nullifier) internal {
        if (self.usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }
        self.usedNullifiers[nullifier] = true;
    }

    function isUsed(Tree storage self, uint256 nullifier) internal view returns (bool) {
        return self.usedNullifiers[nullifier];
    }

    function isValidRoot(Tree storage self, uint256 root) internal view returns (bool) {
        return self.roots[root];
    }

    /// @notice Insert a new nullifier leaf into the indexed Merkle tree.
    /// @param lowLeafHash  Updated hash of the low leaf: hash(lowLeaf.value, newLeaf.value, appendIndex).
    /// @param lowLeafIndex Position of the low leaf in the tree.
    /// @param newLeafHash  Hash of the new leaf to append: hash(newLeaf.value, lowLeaf.nextValue, lowLeaf.nextIndex).
    /// @param appendIndex  Position where the new leaf is inserted (= nextInsertionIndex before this call).
    /// @param zeros        Precomputed zero hashes for each tree level.
    /// @param filledSubtrees Left-sibling subtree hashes for the current tree frontier.
    /// @dev Membership of the low leaf is not verified on-chain — the circuit guarantees it.
    function addLeaf(
        uint256,
        uint256 lowLeafHash,
        uint256 lowLeafIndex,
        uint256 newLeafHash,
        uint256 appendIndex,
        uint256[32] calldata zeros,
        uint256[32] calldata filledSubtrees
    ) internal pure returns (uint256 newRoot) {
        // Step 1: recompute root after updating the low leaf.
        uint256 h = lowLeafHash;
        uint256 idx = lowLeafIndex;
        for (uint256 i = 0; i < 32; i++) {
            h = (idx & 1) == 0
                ? Poseidon2.hashTwo(h, zeros[i])
                : Poseidon2.hashTwo(filledSubtrees[i], h);
            idx >>= 1;
        }

        // Step 2: append new leaf at appendIndex.
        h = newLeafHash;
        idx = appendIndex;
        for (uint256 i = 0; i < 32; i++) {
            h = (idx & 1) == 0
                ? Poseidon2.hashTwo(h, zeros[i])
                : Poseidon2.hashTwo(filledSubtrees[i], h);
            idx >>= 1;
        }

        return h;
    }

    function emptyRoot() internal pure returns (uint256) {
        uint256 h = Poseidon2.hashTwo(0, 0);
        for (uint256 i = 0; i < 31; i++) {
            h = Poseidon2.hashTwo(h, h);
        }
        return h;
    }
}
