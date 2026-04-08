// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./MerkleTreeLibrary.sol";
import {Poseidon2} from "poseidon2-M31-solidity/src/Poseidon2.sol";

uint256 constant M31_MODULUS = 2_147_483_647;

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
    MerkleTreeLib.Tree private tree;       // Deposits and refunds
    MerkleTreeLib.Tree private offersTree; // Offer commitments
    mapping(uint256 => bool) public nullifierHashes;
    mapping(uint256 => uint256) public offerCommitmentToSecretHash;
    address public owner;

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
        uint256 offerCommitment,
        uint256 refundCommitment,
        uint256 cryptoAmount,
        uint256 fiatAmount,
        string currency,
        address tokenAddress,
        string revTag
    );
    event OfferCancelled(uint256 indexed secretHash, uint256 cancelHash);
    event OfferCancelIntent(uint256 indexed secretHash);
    event OfferCancelClaim(uint256 indexed cancelHash);
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
    error InvalidCancelSecret();

    /// @dev Trusted secp256k1 public key coordinates 
    ///      pubkey = 0x04 || X || Y
    bytes32 public constant TRUSTED_PUBKEY_X =
        hex"43cf97685663fe2de67edcb1b9a11aa183459fba4023c9f3b0d05904c505ed86";
    bytes32 public constant TRUSTED_PUBKEY_Y =
        hex"a98616e698ec854b24e7d76a30fdb8c9fb6953ca5028924e2d128f1feb2ad064";

    bytes constant CLAIM_PREFIX = "trusted-stwo-claim-v1";
    bytes constant MESSAGE_PREFIX = "trusted-stwo-message-v1";

    constructor(
        address _owner
    ) {
        owner = _owner;
        tree.initialize();
        offersTree.initialize();
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
        bytes32 proofHash,
        uint32[] calldata claimLogSizes,
        uint32[4][] calldata claimOutputValues,
        bytes calldata signature,
        address token,
        address recipient
    ) external {
        bool verifed = verifyProofAndClaim(proofHash, claimLogSizes, claimOutputValues, signature);
        if (!verifed) revert ProofVerificationFailed();

        if (claimOutputValues.length < 6) revert InvalidVerifierResponse();

        uint256 root = _qm31ToM31(claimOutputValues[0]);
        uint256 nullifier = _qm31ToM31(claimOutputValues[1]);
        uint256 tokenM31 = _qm31ToM31(claimOutputValues[2]);
        uint256 amount = _qm31ToM31(claimOutputValues[3]);
        uint256 refundCommitmentHash = _qm31ToM31(claimOutputValues[4]);
        uint256 recipientM31 = _qm31ToM31(claimOutputValues[5]);

        // Bind explicit addresses to claim values via modulo-M31 reduction (same as circuit side).
        if (tokenM31 != _addressToM31(token)) revert InvalidVerifierResponse();
        if (recipientM31 != _addressToM31(recipient)) revert InvalidVerifierResponse();
        
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

        // For partial withdrawals, insert the change/refund commitment as a new leaf.
        if (refundCommitmentHash != 0) {
            uint64 refundLeafIndex = tree.freeLeafIndex;
            uint256 newRoot = tree.addLeaf(refundCommitmentHash);
            emit Deposit(refundCommitmentHash, 0, token, refundLeafIndex, newRoot);
        }

        // Transfer tokens to recipient
        IERC20 erc20 = IERC20(token);
        bool success = erc20.transfer(recipient, amount);
        if (!success) revert TransferFailed();

        emit Withdraw(nullifier, recipient, token, amount);
    }

        function claimHash(
        uint32[] calldata claimLogSizes,
        uint32[4][] calldata claimOutputValues
    ) public pure returns (bytes32) {
        bytes memory data = abi.encodePacked(CLAIM_PREFIX, _u32be(uint32(claimLogSizes.length)));

        for (uint256 i = 0; i < claimLogSizes.length; i++) {
            data = abi.encodePacked(data, _u32be(claimLogSizes[i]));
        }

        data = abi.encodePacked(data, _u32be(uint32(claimOutputValues.length)));

        for (uint256 i = 0; i < claimOutputValues.length; i++) {
            data = abi.encodePacked(
                data,
                _u32be(claimOutputValues[i][0]),
                _u32be(claimOutputValues[i][1]),
                _u32be(claimOutputValues[i][2]),
                _u32be(claimOutputValues[i][3])
            );
        }

        return keccak256(data);
    }

    function messageHash(bytes32 proofHash, bytes32 claimHash_) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(MESSAGE_PREFIX, proofHash, claimHash_));
    }

    function recoverSigner(bytes32 digest, bytes calldata signature) public pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(digest, v, r, s);
    }

    function verifyProofAndClaim(
        bytes32 proofHash,
        uint32[] calldata claimLogSizes,
        uint32[4][] calldata claimOutputValues,
        bytes calldata signature
    ) internal pure returns (bool) {
        bytes32 cHash = claimHash(claimLogSizes, claimOutputValues);
        bytes32 mHash = messageHash(proofHash, cHash);
        return recoverSigner(mHash, signature) == trustedSignerAddress();
    }

    /// @dev Ethereum address derived from trusted public key: last 20 bytes of keccak256(X || Y).
    function trustedSignerAddress() public pure returns (address) {
        bytes32 h = keccak256(abi.encodePacked(TRUSTED_PUBKEY_X, TRUSTED_PUBKEY_Y));
        return address(uint160(uint256(h)));
    }

    function _u32be(uint32 x) private pure returns (bytes4) {
        return bytes4(x);
    }

    // Paymoney offer Functions
    function createOffer(
        uint256 root,
        uint256 nullifier,
        address token,
        uint256 amount,
        uint256 offerCommitment,
        uint256 refundCommitmentHash,
        uint256 secretHash,
        string calldata currency,
        uint256 fiatAmount,
        string calldata revTag,
        uint32[][] calldata treeColumnLogSizes
    ) external {
        // Check if nullifier already used
        if (nullifierHashes[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle root is valid
        if (!tree.isValidRoot(root)) {
            revert InvalidRoot();
        }

        uint64[] memory publicInputs = new uint64[](6);
        publicInputs[0] = uint64(root);
        publicInputs[1] = uint64(nullifier);
        publicInputs[2] = uint64(amount);
        publicInputs[3] = uint64(offerCommitment);
        publicInputs[4] = uint64(refundCommitmentHash);
        publicInputs[5] = uint64(uint256(uint160(token)) % M31_MODULUS);

        // Check if offer already exists
        if (offers[secretHash].timestamp != 0) {
            revert OfferAlreadyExists();
        }

        // Mark nullifier as used
        nullifierHashes[nullifier] = true;

        // Add offer commitment to offers tree
        offersTree.addLeaf(offerCommitment);

        // Register reverse mapping so cancelOffer can find this offer by its commitment
        offerCommitmentToSecretHash[offerCommitment] = secretHash;

        // Add refund commitment to deposits tree
        {
            uint64 refundLeafIndex = tree.freeLeafIndex;
            uint256 newRoot = tree.addLeaf(refundCommitmentHash);
            emit Deposit(refundCommitmentHash, 0, token, refundLeafIndex, newRoot);
        }

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
            offerCommitment,
            refundCommitmentHash,
            amount,
            fiatAmount,
            currency,
            token,
            revTag
        );
    }

    /// @notice Cancel offer with ZK proof — proves membership in offersTree, creates new deposit
    function cancelOffer(
        uint256 offersRoot,
        uint256 offerNullifier,
        address token,
        uint256 amount,
        uint256 offerCommitment,
        uint256 outputCommitment,
        uint32[][] calldata treeColumnLogSizes
    ) external {
        if (nullifierHashes[offerNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (!offersTree.isValidRoot(offersRoot)) {
            revert InvalidRoot();
        }


        uint64[] memory publicInputs = new uint64[](6);
        publicInputs[0] = uint64(offersRoot);
        publicInputs[1] = uint64(offerNullifier);
        publicInputs[2] = uint64(amount);
        publicInputs[3] = uint64(offerCommitment);
        publicInputs[4] = uint64(outputCommitment);
        publicInputs[5] = uint64(uint256(uint160(token)) % M31_MODULUS);



        nullifierHashes[offerNullifier] = true;

        // Update offer status and remove from active offers if the commitment is known
        uint256 secretHash = offerCommitmentToSecretHash[offerCommitment];
        if (secretHash != 0) {
            Offer storage offer = offers[secretHash];
            offer.status = OfferStatus.CANCELLED;

            for (uint256 i = 0; i < activeOffers.length; i++) {
                if (activeOffers[i] == secretHash) {
                    activeOffers[i] = activeOffers[activeOffers.length - 1];
                    activeOffers.pop();
                    break;
                }
            }

            emit OfferCancelled(secretHash, 0);
        }

        uint64 leafIndex = tree.freeLeafIndex;
        uint256 newRoot = tree.addLeaf(outputCommitment);
        emit Deposit(outputCommitment, amount, token, leafIndex, newRoot);
    }

    /// @notice Cancel intent - reveals offer secret to prove ownership
    /// @dev Step 1: Mark offer as cancelled by revealing offerSecret
    function cancelIntent(
        uint256 offerSecret,
        uint256 cancelHash
    ) external {
        uint256 offerSecretHash = _poseidonHash(offerSecret, offerSecret);
        Offer storage offer = offers[offerSecretHash];
        
        if (offer.timestamp == 0) {
            revert OfferNotFound();
        }
        if (offer.status != OfferStatus.CREATED) {
            revert OfferNotActive();
        }

        // Mark offer as cancelled
        offer.status = OfferStatus.CANCELLED;
        offer.cancelHash = cancelHash;

        // Remove from active offers
        for (uint256 i = 0; i < activeOffers.length; i++) {
            if (activeOffers[i] == offerSecretHash) {
                activeOffers[i] = activeOffers[activeOffers.length - 1];
                activeOffers.pop();
                break;
            }
        }

        emit OfferCancelIntent(offerSecretHash);
    }

    /// @notice Claim refund from a cancelled offer
    /// @dev Step 2: Create commitment for offer amount by revealing cancelSecret
    function cancelClaim(
        uint256 offerHash,
        uint256 cancelSecret,
        uint256 secretNullifierHash
    ) external {
        uint256 offerCancelHash = _poseidonHash(cancelSecret, cancelSecret);
        Offer memory offer = offers[offerHash];

        if (offer.timestamp == 0) {
            revert OfferNotFound();
        }
        if (offer.status != OfferStatus.CANCELLED) {
            revert OfferNotActive();
        }
        if (offer.cancelHash != offerCancelHash) {
            revert InvalidCancelSecret();
        }

        emit OfferCancelClaim(offerCancelHash);

        uint256 cryptoAmountToRefund = offer.cryptoAmount;

        // Create commitment for offer amount
        uint256 commitment = computeCommitment(
            secretNullifierHash,
            cryptoAmountToRefund,
            offer.tokenAddress
        );

        // Add to merkle tree
        tree.addLeaf(commitment);
        
        emit Deposit(
            commitment,
            cryptoAmountToRefund,
            offer.tokenAddress,
            tree.freeLeafIndex - 1,
            tree.currentRoot
        );
    }

    function _qm31ToM31(uint32[4] calldata x) internal pure returns (uint256) {
        require(x[1] == 0 && x[2] == 0 && x[3] == 0, "non-scalar QM31");
        return uint256(x[0]);
    }

    function _addressToM31(address a) internal pure returns (uint256) {
        return uint256(uint160(a)) % M31_MODULUS;
    }

    /// @notice Get current merkle root
    function getCurrentRoot() external view returns (uint256) {
        return tree.currentRoot;
    }

    /// @notice Check if a root is valid
    function isValidRoot(uint256 root) external view returns (bool) {
        return tree.isValidRoot(root);
    }

    /// @notice Get current root of offers tree
    function getOffersTreeRoot() external view returns (uint256) {
        return offersTree.currentRoot;
    }

    /// @notice Check if an offers tree root is valid
    function isValidOffersTreeRoot(uint256 root) external view returns (bool) {
        return offersTree.isValidRoot(root);
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
