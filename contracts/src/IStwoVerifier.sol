// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

struct CM31 {
    uint32 real;
    uint32 imag;
}

struct QM31 {
    CM31 first;
    CM31 second;
}

struct FriConfig {
    uint32 logBlowupFactor;
    uint32 logLastLayerDegreeBound;
    uint256 nQueries;
}

struct StwoConfig {
    uint32 powBits;
    FriConfig friConfig;
}

struct Decommitment {
    bytes32[] witness;
    uint32[] columnWitness;
}

struct FriLayerProof {
    QM31[] friWitness;
    bytes decommitment;
    bytes32 commitment;
}

struct FriProof {
    FriLayerProof firstLayer;
    FriLayerProof[] innerLayers;
    QM31[] lastLayerPoly;
}

struct CompositionPoly {
    uint32[] coeffs0;
    uint32[] coeffs1;
    uint32[] coeffs2;
    uint32[] coeffs3;
}

struct StwoProof {
    StwoConfig config;
    bytes32[] commitments;
    QM31[][][] sampledValues;
    Decommitment[] decommitments;
    uint32[][] queriedValues;
    uint64 proofOfWork;
    FriProof friProof;
    CompositionPoly compositionPoly;
}

struct ComponentInfo {
    uint32 maxConstraintLogDegreeBound;
    uint32 logSize;
    int32[][][] maskOffsets;
    uint256[] preprocessedColumns;
}

struct ComponentParams {
    uint32 logSize;
    QM31 claimedSum;
    ComponentInfo info;
}

struct VerificationParams {
    ComponentParams[] componentParams;
    uint256 nPreprocessedColumns;
    uint32 componentsCompositionLogDegreeBound;
    uint32 nInteractionDraws;
    QM31[] interactionMixFelts;
}

interface IStwoVerifier {
    function verify(
        StwoProof calldata proof,
        VerificationParams calldata params,
        uint32[][] calldata treeColumnLogSizes,
        uint64[] calldata publicInputs
    ) external returns (bool);
}