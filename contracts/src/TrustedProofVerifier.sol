// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TrustedProofVerifier
/// @notice Verifies an EVM-compatible secp256k1 signature over
///         keccak256("trusted-stwo-message-v1" || proofHash || claimHash).
///         The claim hash is recomputed on-chain from raw public inputs.
contract TrustedProofVerifier {
    /// @dev Trusted secp256k1 public key coordinates 
    ///      pubkey = 0x04 || X || Y
    bytes32 public constant TRUSTED_PUBKEY_X =
        hex"43cf97685663fe2de67edcb1b9a11aa183459fba4023c9f3b0d05904c505ed86";
    bytes32 public constant TRUSTED_PUBKEY_Y =
        hex"a98616e698ec854b24e7d76a30fdb8c9fb6953ca5028924e2d128f1feb2ad064";

    bytes constant CLAIM_PREFIX = "trusted-stwo-claim-v1";
    bytes constant MESSAGE_PREFIX = "trusted-stwo-message-v1";

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
    ) external pure returns (bool) {
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
}
