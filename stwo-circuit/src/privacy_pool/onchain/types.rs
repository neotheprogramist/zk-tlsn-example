use alloy::{primitives::FixedBytes, sol};

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
    }

    interface IStwoVerifier {
        function verify(
            Proof calldata proof,
            VerificationParams calldata params,
            bytes32[] memory treeRoots,
            uint32[][] memory treeColumnLogSizes,
            bytes32 digest,
            uint32 nDraws
        ) external view returns (bool);
    }

    interface IPrivacyPool {
        function withdraw(
            uint256 root,
            uint256 nullifier,
            address token,
            uint256 amount,
            address recipient,
            bytes calldata verifyCalldata
        ) external;
    }
}

pub struct OnchainVerificationInput {
    pub proof: Proof,
    pub params: VerificationParams,
    pub tree_roots: Vec<FixedBytes<32>>,
    pub tree_column_log_sizes: Vec<Vec<u32>>,
    pub digest: FixedBytes<32>,
    pub n_draws: u32,
}
