use alloy::sol;

sol! {
    struct QM31 {
        CM31 first;
        CM31 second;
    }

    struct CM31 {
        uint32 real;
        uint32 imag;
    }

    struct Config {
        uint32 powBits;
        FriConfig friConfig;
    }

    struct FriConfig {
        uint32 logBlowupFactor;
        uint32 logLastLayerDegreeBound;
        uint256 nQueries;
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

    struct Proof {
        Config config;
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
            Proof calldata proof,
            VerificationParams calldata params,
            uint32[][] memory treeColumnLogSizes,
            uint64[] calldata publicInputs
        ) external view returns (bool);
    }

    interface IPrivacyPool {
        function withdraw(
            uint256 root,
            uint256 nullifier,
            address token,
            uint256 amount,
            address recipient,
            uint256 refundCommitmentHash,
            bytes calldata verifyCalldata
        ) external;
    }
}

pub struct OnchainVerificationInput {
    pub proof: Proof,
    pub params: VerificationParams,
    pub tree_column_log_sizes: Vec<Vec<u32>>,
    pub public_inputs: Vec<u64>,
}
