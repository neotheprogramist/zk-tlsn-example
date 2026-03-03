// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Poseidon2} from "poseidon2-M31-solidity/src/Poseidon2.sol";

library MerkleTreeLib {
    struct Tree {
        uint64 freeLeafIndex;
        uint256 currentRoot;
        mapping(uint256 => bool) roots;
        mapping(uint256 => bool) usedCommitments;
        uint256[32] precomputed;
        uint256[32] leftPath;
        uint256[] rootsHistory;
    }
    
    event LeafAdded(address indexed caller, uint256 indexed commitment, uint256 newRoot);
    
    error DuplicateCommitment();
    error TreeFull();
    
    function initialize(Tree storage self) internal {
        self.precomputed[0] = Poseidon2.hashTwo(0, 0);
        for (uint256 i = 1; i < 32; i++) {
            self.precomputed[i] = Poseidon2.hashTwo(self.precomputed[i - 1], self.precomputed[i - 1]);
        }

        for (uint256 i = 0; i < 32; i++) {
            self.leftPath[i] = self.precomputed[i];
        }

        self.currentRoot = self.precomputed[31];
        self.roots[self.currentRoot] = true;
        self.rootsHistory.push(self.currentRoot);
        self.freeLeafIndex = 0;
    }
    
    function addLeaf(Tree storage self, uint256 commitment) internal returns (uint256 newRoot) {
        if (self.usedCommitments[commitment]) {
            revert DuplicateCommitment();
        }

        if (self.freeLeafIndex >= (1 << 32)) {
            revert TreeFull();
        }

        self.usedCommitments[commitment] = true;
        self.rootsHistory.push(commitment);
        
        uint256 currentHash = commitment;
        uint64 currentIndex = self.freeLeafIndex;
        self.freeLeafIndex++;
        
        for (uint256 i = 1; i < 32; i++) {
            if (currentIndex % 2 == 0) {
                self.leftPath[i - 1] = currentHash;
                currentHash = Poseidon2.hashTwo(currentHash, self.precomputed[i - 1]);
            } else {
                currentHash = Poseidon2.hashTwo(self.leftPath[i - 1], currentHash);
            }
            currentIndex = currentIndex / 2;
        }
        
        self.leftPath[31] = currentHash;
        self.roots[currentHash] = true;
        self.currentRoot = currentHash;
        
        emit LeafAdded(msg.sender, commitment, currentHash);
        
        return currentHash;
    }
    
    function isValidRoot(Tree storage self, uint256 root) internal view returns (bool) {
        return self.roots[root];
    }

    /// @notice Register a known root for testing/integration flows
    function registerKnownRoot(Tree storage self, uint256 root) internal {
        self.roots[root] = true;
        self.currentRoot = root;
        self.rootsHistory.push(root);
    }

    function isUsedCommitment(Tree storage self, uint256 commitment) internal view returns (bool) {
        return self.usedCommitments[commitment];
    }

    function getZeroHash(Tree storage self, uint256 level) internal view returns (uint256) {
        require(level < 32, "Invalid level");
        return self.precomputed[level];
    }

    function getLeftPath(Tree storage self, uint256 level) internal view returns (uint256) {
        require(level < 32, "Invalid level");
        return self.leftPath[level];
    }
}
