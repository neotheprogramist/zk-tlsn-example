// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Poseidon2} from "poseidon2-M31-solidity/Poseidon2.sol";

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
        self.precomputed[0] = 0x8578fcabbd43194e30b13054685cf3002b5e21c0a2064fe707b10d27351afe6;
        self.precomputed[1] = 0x228539256bbe39498a6664fd272b0830a1bf57da3f05f25a516a1ddef5f4390;
        self.precomputed[2] = 0x1742dae20f4da6deaf6b0b45d2bd51a002c04d91e1c4fc1b68b841b4e902740;
        self.precomputed[3] = 0xcab749aded72070aeaf9e4ccdacebe50d7d9d87f0fcca935c553a1af8e4d57c;
        self.precomputed[4] = 0xcdd8b0aa9ae7040d9567044d6e1772d06be7a800e0fc7f7adbf98244e764ab3;
        self.precomputed[5] = 0xe245a8e48f1559c9c1946bb162ccddb03212bf0de957c5f595519867257d7acb;
        self.precomputed[6] = 0xbf802c662e5d7f5d2736570d4d87a090be6e94f06106c091ed8e48e24bd370b;
        self.precomputed[7] = 0xf84c558053b0aa09301f5d545d1220501529499066e65de4e260294a090e74a;
        self.precomputed[8] = 0xd5a8e1cf918158ce2f10be5e856b4490b467080153b264d2aad1f2ee77d2c99;
        self.precomputed[9] = 0x174ee7e6f0e5825d08331b32e465b700d7bd1ed2f8373466439260e4060ccdc;
        self.precomputed[10] = 0x592121412b2cd9a5bc383da5cc057e901790f92a53beae17b5722e1efc919a5;
        self.precomputed[11] = 0x58f25f6f34dc8eb17508006716121e2093b436e1063634c07f7814381eb6f34;
        self.precomputed[12] = 0xffee13c1091502f5925b5d0adec1b3e0fd290902443ed1a596142ee2342dbbe;
        self.precomputed[13] = 0x1f6d3c59906966c0173dda27e35f01c0d513d1171bdc9ab7b5b07becac4e50e;
        self.precomputed[14] = 0x95fb6b024506baa2c17dd37f317d84d060dbfe16c9bd3068be88f2784edbc80;
        self.precomputed[15] = 0x63abed0a017192b39e670cea77864e807a4fc6b679be07aaa819bafd4ac57b7;
        self.precomputed[16] = 0x589d3652d806a60cf31f891993d3d6e0dba02fb174758d645fb2b2406a2517d;
        self.precomputed[17] = 0xc0aa25388c7ae53a1f92a7e9c4933c500745d1427573ae159bf59c3520c5e17;
        self.precomputed[18] = 0xd50033c1c0024fd9ff14a365ccd003b02c3cd2202ba3d83f577fe6162130c8b;
        self.precomputed[19] = 0x369e86479266da3a25bd7909690f0350959b3415d71aa1ff83c5d824c1f299e;
        self.precomputed[20] = 0x970ce58bf2750c3c1ec9dfcc892c270003c0990aab372ce6a1b1d5ff895ca75;
        self.precomputed[21] = 0x365f34c9658540ce16570dc706a70f60f489ac825c45ecc1723bb20e8ae54cc;
        self.precomputed[22] = 0x47828c635acab3f612a7b26d1401a3609502161441beb002f1bc41f4813ada1;
        self.precomputed[23] = 0xb6d9a6bb05adf2874ba6327d3d858cf04bdb315c39b483b5a4746a6f36a9b91;
        self.precomputed[24] = 0x73e62784a45dbe760b9c6b2546f839505bf5226ea636f622dfc76661be10d78;
        self.precomputed[25] = 0x9d1ff55291ca56c8b942ac3df78705b09550aeae677cc0b91a7d5d2799d96de;
        self.precomputed[26] = 0x34cfb1ba8153cc6f9657bb285cbc36f09d5375bfc6c030b1d25d8f1e7475e91;
        self.precomputed[27] = 0x66ebbd3c183db10c3710086121137e20fd4c61b6f0d7e0d742b57b18b8ec504;
        self.precomputed[28] = 0x98b5ab585744e7c9d20083ef313f8420473568d90818128d3752a69094bdcf6;
        self.precomputed[29] = 0x48776311590a47069dc2ad06a1c0abc03c5c5bc713027d7d1ed1107e8c4f134;
        self.precomputed[30] = 0x42ce99c0e60f866afa8a78c23e7b079062402bdd61baa7c6159f8e3bba8a54f;
        self.precomputed[31] = 0x9dc184d20f0058512d9643bec21e2d0f7f8af5cdfcb189fc13d620882a37f8;
        
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

    function isUsedCommitment(Tree storage self, uint256 commitment) internal view returns (bool) {
        return self.usedCommitments[commitment];
    }
}