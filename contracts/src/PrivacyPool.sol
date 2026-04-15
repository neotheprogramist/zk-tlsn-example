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

enum TransactionStatus {
    PENDING,
    SUCCESS,
    REJECTED
}

struct Offer {
    address tokenAddress;
    OfferStatus status;
    uint256 cryptoAmount;
    uint256 timestamp;
    // H(offer_refund_secret, offer_refund_nullifier) — seller's key embedded in offerCommitment;
    // used to create a seller refund deposit for the remaining amount after first use or cancel.
    uint256 offerRefundSecretNullifierHash;
}

struct Transaction {
    uint256 cryptoAmount;
    uint256 expiresAt;
    TransactionStatus status;
    string randomTitle;
    address tokenAddress;
    uint256 timestamp;
    uint256 offerSecretHash;
    address buyer;
}

contract PrivacyPool {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    mapping(uint256 => Offer) public offers;
    uint256[] public activeOffers;
    mapping(bytes32 => Transaction) public transactions;
    mapping(string => bytes32) public titleToTransactionId;
    mapping(uint256 => bytes32[]) public offerTransactions;
    mapping(uint256 => uint256) public offerReservedAmount;
    mapping(uint256 => bool) public nullifiers;
    /// @dev Separate nullifier set for offer spend/cancel proofs (offersTree membership).
    ///      Distinct from `nullifiers` (depositsTree) so the two domains cannot collide.
    mapping(uint256 => bool) public offerNullifiers;

    MerkleTreeLib.Tree private tree;
    MerkleTreeLib.Tree private offersTree;
    mapping(uint256 => uint256) public offerCommitmentToSecretHash;
    address public owner;

    event Deposit(
        uint256 indexed commitment,
        uint256 amount,
        address indexed token,
        uint64 leafIndex,
        uint256 newRoot
    );
    event Withdraw(
        uint256 indexed nullifier,
        address indexed recipient,
        address token,
        uint256 amount
    );
    event OfferCreated(
        uint256 indexed offerCommitment,
        uint256 indexed secretHash,
        address indexed tokenAddress,
        uint256 cryptoAmount
    );
    event TransactionCreated(
        bytes32 indexed transactionId,
        uint256 indexed offerSecretHash,
        uint256 cryptoAmount,
        address indexed buyer
    );
    event TransactionVerified(bytes32 indexed transactionId, uint256 cryptoAmount);
    event OfferCancelled(uint256 indexed offerNullifierHash, uint256 indexed offerCommitment);

    error TransferFailed();
    error NullifierAlreadyUsed();
    error InvalidRoot();
    error OfferNotFound();
    error OfferAlreadyExists();
    error OfferNotActive();
    error ProofVerificationFailed();
    error TransactionNotFound();
    error TransactionNotPending();
    error TransactionExpired();
    error InvalidSettlementSignature();
    error InsufficientOfferLiquidity();
    error TitleAlreadyUsed();
    error UnauthorizedTransactionVerifier();
    error InvalidVerifierResponse();

    /// @dev Trusted secp256k1 public key coordinates — pubkey = 0x04 || X || Y
    bytes32 public constant TRUSTED_PUBKEY_X =
        hex"43cf97685663fe2de67edcb1b9a11aa183459fba4023c9f3b0d05904c505ed86";
    bytes32 public constant TRUSTED_PUBKEY_Y =
        hex"a98616e698ec854b24e7d76a30fdb8c9fb6953ca5028924e2d128f1feb2ad064";

    bytes constant CLAIM_PREFIX = "trusted-stwo-claim-v1";
    bytes constant MESSAGE_PREFIX = "trusted-stwo-message-v1";

    constructor(address _owner) {
        owner = _owner;
        tree.initialize();
        offersTree.initialize();
    }

    // ── Public helpers ────────────────────────────────────────────────────────

    function poseidonHash(uint256 left, uint256 right) public pure returns (uint256) {
        return Poseidon2.hashTwo(left, right);
    }

    function computeCommitment(
        uint256 secretNullifierHash,
        uint256 amount,
        address token
    ) public pure returns (uint256) {
        uint256 h = Poseidon2.hashTwo(secretNullifierHash, amount);
        return Poseidon2.hashTwo(h, uint256(uint160(token)));
    }

    function trustedSignerAddress() public pure returns (address) {
        bytes32 h = keccak256(abi.encodePacked(TRUSTED_PUBKEY_X, TRUSTED_PUBKEY_Y));
        return address(uint160(uint256(h)));
    }

    function messageHash(bytes32 claimHash_) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(MESSAGE_PREFIX, claimHash_));
    }

    function recoverSigner(
        bytes32 digest,
        bytes calldata signature
    ) public pure returns (address) {
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

    function executionHash(
        uint256 root,
        uint256 nullifier,
        uint256 tokenM31,
        uint256 amount,
        uint256 aux1,
        uint256 aux2
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    CLAIM_PREFIX,
                    _u32be(_m31ToU32(root)),
                    _u32be(_m31ToU32(nullifier)),
                    _u32be(_m31ToU32(tokenM31)),
                    _u32be(_m31ToU32(amount)),
                    _u32be(_m31ToU32(aux1)),
                    _u32be(_m31ToU32(aux2))
                )
            );
    }

    function settlementExecutionHash(
        bytes32 transactionId,
        uint256 fiatAmount,
        uint256 cryptoAmount,
        uint256 secretNullifierHash,
        address buyer,
        address token
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    CLAIM_PREFIX,
                    transactionId,
                    _u256be(fiatAmount),
                    _u256be(cryptoAmount),
                    _u256be(secretNullifierHash),
                    buyer,
                    token
                )
            );
    }

    function getAvailableOfferAmount(
        uint256 offerSecretHash
    ) public view returns (uint256) {
        Offer storage offer = offers[offerSecretHash];
        if (
            offer.timestamp == 0 ||
            offer.cryptoAmount <= offerReservedAmount[offerSecretHash]
        ) {
            return 0;
        }
        return offer.cryptoAmount - offerReservedAmount[offerSecretHash];
    }

    // ── Core protocol ─────────────────────────────────────────────────────────

    function deposit(
        uint256 secretNullifierHash,
        uint256 amount,
        address token
    ) external {
        uint64 leafIndex = tree.freeLeafIndex;
        uint256 commitment = computeCommitment(secretNullifierHash, amount, token);
        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (!success) revert TransferFailed();
        uint256 newRoot = tree.addLeaf(commitment);
        emit Deposit(commitment, amount, token, leafIndex, newRoot);
    }

    function withdraw(
        uint256 root,
        uint256 nullifier,
        uint256 amount,
        uint256 refundCommitmentHash,
        bytes calldata signature,
        address token,
        address recipient
    ) external {
        uint256 tokenM31 = _addressToM31(token);
        uint256 recipientM31 = _addressToM31(recipient);
        if (
            !_verifySignature6(
                root,
                nullifier,
                tokenM31,
                amount,
                refundCommitmentHash,
                recipientM31,
                signature
            )
        ) {
            revert ProofVerificationFailed();
        }
        if (!tree.isValidRoot(root)) revert InvalidRoot();
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed();
        nullifiers[nullifier] = true;

        if (refundCommitmentHash != 0) {
            uint64 refundLeafIndex = tree.freeLeafIndex;
            uint256 newRoot = tree.addLeaf(refundCommitmentHash);
            emit Deposit(refundCommitmentHash, 0, token, refundLeafIndex, newRoot);
        }
        bool success = IERC20(token).transfer(recipient, amount);
        if (!success) revert TransferFailed();
        emit Withdraw(nullifier, recipient, token, amount);
    }

    /// @notice Create an offer from a ZK proof.
    /// @dev claimOutputValues (7 M31 scalars from offer circuit):
    ///   [0] depositsRoot  [1] nullifier  [2] tokenM31  [3] amount
    ///   [4] offerCommitment  [5] refundCommitment  [6] offerRefundSnHash
    function createOffer(
        uint32[4][] calldata claimOutputValues,
        bytes calldata signature,
        address token,
        uint256 secretHash
    ) external {
        if (claimOutputValues.length < 7) revert InvalidVerifierResponse();

        uint256 root = _qm31ToM31(claimOutputValues[0]);
        uint256 nullifier = _qm31ToM31(claimOutputValues[1]);
        uint256 tokenM31 = _qm31ToM31(claimOutputValues[2]);
        uint256 amount = _qm31ToM31(claimOutputValues[3]);
        uint256 offerCommitment = _qm31ToM31(claimOutputValues[4]);
        uint256 refundCommitment = _qm31ToM31(claimOutputValues[5]);
        uint256 offerRefundSnHash = _qm31ToM31(claimOutputValues[6]);

        if (
            !_verifySignature7(
                root,
                nullifier,
                tokenM31,
                amount,
                offerCommitment,
                refundCommitment,
                offerRefundSnHash,
                signature
            )
        ) {
            revert ProofVerificationFailed();
        }
        if (tokenM31 != _addressToM31(token)) revert InvalidVerifierResponse();
        if (!tree.isValidRoot(root)) revert InvalidRoot();
        if (offers[secretHash].timestamp != 0) revert OfferAlreadyExists();
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed();
        nullifiers[nullifier] = true;

        offersTree.addLeaf(offerCommitment);
        offerCommitmentToSecretHash[offerCommitment] = secretHash;

        {
            uint64 refundLeafIndex = tree.freeLeafIndex;
            uint256 newRoot = tree.addLeaf(refundCommitment);
            emit Deposit(refundCommitment, 0, token, refundLeafIndex, newRoot);
        }

        offers[secretHash] = Offer({
            tokenAddress: token,
            status: OfferStatus.CREATED,
            cryptoAmount: amount,
            timestamp: block.timestamp,
            offerRefundSecretNullifierHash: offerRefundSnHash
        });

        activeOffers.push(secretHash);

        emit OfferCreated(offerCommitment, secretHash, token, amount);
    }

    function createTransaction(
        uint256 offerSecretHash,
        uint256 cryptoAmount,
        string calldata title
    ) external returns (bytes32) {
        Offer storage offer = offers[offerSecretHash];
        if (offer.timestamp == 0) revert OfferNotFound();
        if (offer.status != OfferStatus.CREATED) revert OfferNotActive();
        if (bytes(title).length == 0) revert InvalidVerifierResponse();
        if (titleToTransactionId[title] != bytes32(0)) revert TitleAlreadyUsed();

        uint256 available = getAvailableOfferAmount(offerSecretHash);
        if (cryptoAmount == 0 || cryptoAmount > available) {
            revert InsufficientOfferLiquidity();
        }

        bytes32 transactionId = keccak256(
            abi.encodePacked(
                offerSecretHash,
                msg.sender,
                title,
                block.timestamp,
                cryptoAmount
            )
        );

        transactions[transactionId] = Transaction({
            cryptoAmount: cryptoAmount,
            expiresAt: block.timestamp + 120 minutes,
            status: TransactionStatus.PENDING,
            randomTitle: title,
            tokenAddress: offer.tokenAddress,
            timestamp: block.timestamp,
            offerSecretHash: offerSecretHash,
            buyer: msg.sender
        });

        titleToTransactionId[title] = transactionId;
        offerTransactions[offerSecretHash].push(transactionId);
        offerReservedAmount[offerSecretHash] += cryptoAmount;

        emit TransactionCreated(transactionId, offerSecretHash, cryptoAmount, msg.sender);
        return transactionId;
    }

    /// @notice Settle a transaction: verify fiat payment (TLSN) + offer membership (ZK circuit).
    /// @param settlementSignature  Trusted-server signature over the TLSN settlement claim.
    /// @param offerCircuitOutputs  6 M31 scalars from offer_spend_cancel_circuit:
    ///   [0] offersRoot  [1] offerNullifierHash  [2] tokenM31
    ///   [3] amount      [4] offerCommitment      [5] outputCommitment
    /// @param offerCircuitSignature  Trusted-server signature over the circuit claim.
    function verifyTransaction(
        bytes32 transactionId,
        uint256 fiatAmount,
        uint256 cryptoAmount,
        uint256 secretNullifierHash,
        bytes calldata settlementSignature,
        uint32[4][] calldata offerCircuitOutputs,
        bytes calldata offerCircuitSignature
    ) external {
        Transaction storage txn = transactions[transactionId];
        if (txn.timestamp == 0) revert TransactionNotFound();
        if (txn.status != TransactionStatus.PENDING) revert TransactionNotPending();
        if (txn.expiresAt < block.timestamp) revert TransactionExpired();
        if (txn.buyer != msg.sender) revert UnauthorizedTransactionVerifier();
        if (cryptoAmount == 0 || cryptoAmount > txn.cryptoAmount) {
            revert InvalidVerifierResponse();
        }

        // 1) Verify TLSN settlement signature (proves fiat payment happened).
        bytes32 cHash = settlementExecutionHash(
            transactionId,
            fiatAmount,
            cryptoAmount,
            secretNullifierHash,
            msg.sender,
            txn.tokenAddress
        );
        if (recoverSigner(messageHash(cHash), settlementSignature) != trustedSignerAddress()) {
            revert InvalidSettlementSignature();
        }

        // 2) Verify offer circuit proof (proves offer membership in offersTree + spend nullifier).
        if (offerCircuitOutputs.length < 6) revert InvalidVerifierResponse();
        uint256 offersRoot      = _qm31ToM31(offerCircuitOutputs[0]);
        uint256 offerNullifier  = _qm31ToM31(offerCircuitOutputs[1]);
        uint256 offerTokenM31   = _qm31ToM31(offerCircuitOutputs[2]);
        uint256 offerAmount     = _qm31ToM31(offerCircuitOutputs[3]);
        uint256 offerCommitment = _qm31ToM31(offerCircuitOutputs[4]);
        uint256 outputCommitment = _qm31ToM31(offerCircuitOutputs[5]);

        if (
            !_verifySignature6(
                offersRoot,
                offerNullifier,
                offerTokenM31,
                offerAmount,
                offerCommitment,
                outputCommitment,
                offerCircuitSignature
            )
        ) revert ProofVerificationFailed();

        if (!offersTree.isValidRoot(offersRoot)) revert InvalidRoot();
        if (offerNullifiers[offerNullifier]) revert NullifierAlreadyUsed();
        // Bind circuit proof to the offer being settled: commitment must map to the same offer.
        if (offerCommitmentToSecretHash[offerCommitment] != txn.offerSecretHash) {
            revert InvalidVerifierResponse();
        }
        if (offerTokenM31 != _addressToM31(txn.tokenAddress)) revert InvalidVerifierResponse();
        offerNullifiers[offerNullifier] = true;

        // 3) Apply settlement state changes.
        txn.status = TransactionStatus.SUCCESS;
        offerReservedAmount[txn.offerSecretHash] -= txn.cryptoAmount;
        offers[txn.offerSecretHash].cryptoAmount -= cryptoAmount;

        // Buyer receives crypto into the deposits tree.
        uint256 buyerCommitment = computeCommitment(
            secretNullifierHash,
            cryptoAmount,
            txn.tokenAddress
        );
        {
            uint64 leafIndex = tree.freeLeafIndex;
            uint256 newRoot = tree.addLeaf(buyerCommitment);
            emit Deposit(buyerCommitment, cryptoAmount, txn.tokenAddress, leafIndex, newRoot);
        }

        // Seller receives remaining offer amount via the refund key embedded in offerCommitment.
        uint256 remaining = offers[txn.offerSecretHash].cryptoAmount;
        if (remaining > 0) {
            uint256 refundSNHash = offers[txn.offerSecretHash].offerRefundSecretNullifierHash;
            uint256 sellerRefund = computeCommitment(
                refundSNHash,
                remaining,
                txn.tokenAddress
            );
            uint64 refundLeafIndex = tree.freeLeafIndex;
            uint256 refundRoot = tree.addLeaf(sellerRefund);
            emit Deposit(
                sellerRefund,
                remaining,
                txn.tokenAddress,
                refundLeafIndex,
                refundRoot
            );
        }

        offers[txn.offerSecretHash].status = OfferStatus.CANCELLED;
        _removeFromActiveOffers(txn.offerSecretHash);

        emit TransactionVerified(transactionId, cryptoAmount);
    }

    /// @notice Cancel offer with ZK proof — proves membership in offersTree, creates seller refund.
    /// @dev claimOutputValues (6 M31 scalars from cancel circuit):
    ///   [0] offersRoot  [1] offerNullifierHash  [2] tokenM31
    ///   [3] amount      [4] offerCommitment      [5] outputCommitment
    function cancelOffer(
        uint32[4][] calldata claimOutputValues,
        bytes calldata signature,
        address token,
        uint256 offerCommitment,
        uint256 outputCommitment
    ) external {
        if (claimOutputValues.length < 6) revert InvalidVerifierResponse();

        uint256 offersRoot = _qm31ToM31(claimOutputValues[0]);
        uint256 offerNullifier = _qm31ToM31(claimOutputValues[1]);
        uint256 tokenM31 = _qm31ToM31(claimOutputValues[2]);
        uint256 amount = _qm31ToM31(claimOutputValues[3]);
        uint256 claimOffer = _qm31ToM31(claimOutputValues[4]);
        uint256 claimOutput = _qm31ToM31(claimOutputValues[5]);

        if (tokenM31 != _addressToM31(token)) revert InvalidVerifierResponse();
        if (claimOffer != offerCommitment) revert InvalidVerifierResponse();
        if (claimOutput != outputCommitment) revert InvalidVerifierResponse();

        if (
            !_verifySignature6(
                offersRoot,
                offerNullifier,
                tokenM31,
                amount,
                offerCommitment,
                outputCommitment,
                signature
            )
        ) {
            revert ProofVerificationFailed();
        }
        if (!offersTree.isValidRoot(offersRoot)) revert InvalidRoot();
        if (offerNullifiers[offerNullifier]) revert NullifierAlreadyUsed();
        offerNullifiers[offerNullifier] = true;

        uint256 secretHash = offerCommitmentToSecretHash[offerCommitment];
        if (secretHash != 0) {
            offers[secretHash].status = OfferStatus.CANCELLED;
            _removeFromActiveOffers(secretHash);
        }

        uint64 leafIndex = tree.freeLeafIndex;
        uint256 newRoot = tree.addLeaf(outputCommitment);
        emit Deposit(outputCommitment, amount, token, leafIndex, newRoot);
        emit OfferCancelled(offerNullifier, offerCommitment);
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    function getCurrentRoot() external view returns (uint256) {
        return tree.currentRoot;
    }

    function isValidRoot(uint256 root) external view returns (bool) {
        return tree.isValidRoot(root);
    }

    function getOffersTreeRoot() external view returns (uint256) {
        return offersTree.currentRoot;
    }

    function isValidOffersTreeRoot(uint256 root) external view returns (bool) {
        return offersTree.isValidRoot(root);
    }

    function isNullifierUsed(uint256 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    function isOfferNullifierUsed(uint256 nullifier) external view returns (bool) {
        return offerNullifiers[nullifier];
    }

    function getNextLeafIndex() external view returns (uint64) {
        return tree.freeLeafIndex;
    }

    function getZeroHash(uint256 level) external view returns (uint256) {
        return tree.getZeroHash(level);
    }

    function getLeftPath(uint256 level) external view returns (uint256) {
        return tree.getLeftPath(level);
    }

    // Legacy compatibility stubs
    function getNullifierTreeRoot() external pure returns (uint256) {
        return 0;
    }

    function isValidNullifierRoot(uint256 root) external pure returns (bool) {
        return root == 0;
    }

    function getIndexedNullifierRoot() external pure returns (uint256) {
        return 0;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _verifySignature6(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d,
        uint256 e,
        uint256 f,
        bytes calldata signature
    ) internal pure returns (bool) {
        bytes32 cHash = executionHash(a, b, c, d, e, f);
        return recoverSigner(messageHash(cHash), signature) == trustedSignerAddress();
    }

    function _verifySignature7(
        uint256 root,
        uint256 nullifier,
        uint256 tokenM31,
        uint256 amount,
        uint256 aux1,
        uint256 aux2,
        uint256 aux3,
        bytes calldata signature
    ) internal pure returns (bool) {
        bytes32 cHash = keccak256(
            abi.encodePacked(
                CLAIM_PREFIX,
                _u32be(_m31ToU32(root)),
                _u32be(_m31ToU32(nullifier)),
                _u32be(_m31ToU32(tokenM31)),
                _u32be(_m31ToU32(amount)),
                _u32be(_m31ToU32(aux1)),
                _u32be(_m31ToU32(aux2)),
                _u32be(_m31ToU32(aux3))
            )
        );
        return recoverSigner(messageHash(cHash), signature) == trustedSignerAddress();
    }

    function _removeFromActiveOffers(uint256 offerSecretHash) internal {
        for (uint256 i = 0; i < activeOffers.length; i++) {
            if (activeOffers[i] == offerSecretHash) {
                activeOffers[i] = activeOffers[activeOffers.length - 1];
                activeOffers.pop();
                break;
            }
        }
    }

    function _qm31ToM31(uint32[4] calldata x) internal pure returns (uint256) {
        require(x[1] == 0 && x[2] == 0 && x[3] == 0, "non-scalar QM31");
        return uint256(x[0]);
    }

    function _addressToM31(address a) internal pure returns (uint256) {
        return uint256(uint160(a)) % M31_MODULUS;
    }

    function _poseidonHash(uint256 left, uint256 right) internal pure returns (uint256) {
        return Poseidon2.hashTwo(left, right);
    }

    function _u32be(uint32 x) private pure returns (bytes4) {
        return bytes4(x);
    }

    function _u256be(uint256 x) private pure returns (bytes32) {
        return bytes32(x);
    }

    function _m31ToU32(uint256 x) private pure returns (uint32) {
        if (x >= M31_MODULUS) revert InvalidVerifierResponse();
        return uint32(x);
    }
}
