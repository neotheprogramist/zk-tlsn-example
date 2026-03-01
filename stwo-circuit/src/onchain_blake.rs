use stwo::{
    core::{
        air::{Component, Components},
        channel::{Channel, KeccakChannel},
        circle::CirclePoint,
        fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField},
        poly::circle::CanonicCoset,
        vcs::keccak_merkle::KeccakMerkleChannel,
        proof::StarkProof,
        utils::bit_reverse,
        vcs::keccak_merkle::KeccakMerkleHasher,
        pcs::CommitmentSchemeVerifier,
    },
    prover::{
        backend::simd::SimdBackend,
        poly::circle::SecureCirclePoly,
    },
};
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, TraceLocationAllocator};

use crate::{
    ProofData,
    blake3::{AllElements, BlakeComponentsForIntegration, BlakeStatement0},
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QM31 {
    pub first: CM31,
    pub second: CM31,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CM31 {
    pub real: u32,
    pub imag: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub pow_bits: u32,
    pub fri_config: FriConfig,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FriConfig {
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Decommitment {
    pub witness: Vec<[u8; 32]>,
    pub column_witness: Vec<u32>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FriLayerProof {
    pub fri_witness: Vec<QM31>,
    pub decommitment: Vec<u8>,
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FriProof {
    pub first_layer: FriLayerProof,
    pub inner_layers: Vec<FriLayerProof>,
    pub last_layer_poly: Vec<QM31>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompositionPoly {
    pub coeffs0: Vec<u32>,
    pub coeffs1: Vec<u32>,
    pub coeffs2: Vec<u32>,
    pub coeffs3: Vec<u32>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub config: Config,
    pub commitments: Vec<[u8; 32]>,
    pub sampled_values: Vec<Vec<Vec<QM31>>>,
    pub decommitments: Vec<Decommitment>,
    pub queried_values: Vec<Vec<u32>>,
    pub proof_of_work: u64,
    pub fri_proof: FriProof,
    pub composition_poly: CompositionPoly,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ComponentInfo {
    pub max_constraint_log_degree_bound: u32,
    pub log_size: u32,
    pub mask_offsets: Vec<Vec<Vec<i32>>>,
    pub preprocessed_columns: Vec<u64>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ComponentParams {
    pub log_size: u32,
    pub claimed_sum: QM31,
    pub info: ComponentInfo,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VerificationParams {
    pub component_params: Vec<ComponentParams>,
    pub n_preprocessed_columns: u64,
    pub components_composition_log_degree_bound: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OnchainVerifyInput {
    pub proof: Proof,
    pub verification_params: VerificationParams,
    pub tree_roots: Vec<[u8; 32]>,
    pub tree_column_log_sizes: Vec<Vec<u32>>,
    pub digest: [u8; 32],
    pub n_draws: u32,
}

fn qm31_to_sol(qm31: stwo::core::fields::qm31::SecureField) -> QM31 {
    QM31 {
        first: CM31 {
            real: qm31.0 .0 .0,
            imag: qm31.0 .1 .0,
        },
        second: CM31 {
            real: qm31.1 .0 .0,
            imag: qm31.1 .1 .0,
        },
    }
}

fn encode_u256_be_from_usize(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let value_u64 = value as u64;
    out[24..].copy_from_slice(&value_u64.to_be_bytes());
    out
}

fn encode_decommitment_packed(hash_witness: &[[u8; 32]], column_witness: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();

    encoded.extend_from_slice(&encode_u256_be_from_usize(hash_witness.len()));

    for witness in hash_witness {
        encoded.extend_from_slice(witness);
    }

    encoded.extend_from_slice(&encode_u256_be_from_usize(column_witness.len()));

    for &value in column_witness {
        encoded.extend_from_slice(&value.to_be_bytes());
    }

    encoded
}

pub fn convert_stark_proof_to_solidity(
    proof: StarkProof<KeccakMerkleHasher>,
    composition_polynomial: SecureCirclePoly<SimdBackend>,
) -> Proof {
    let sol_config = Config {
        pow_bits: proof.config.pow_bits,
        fri_config: FriConfig {
            log_blowup_factor: proof.config.fri_config.log_blowup_factor,
            log_last_layer_degree_bound: proof.config.fri_config.log_last_layer_degree_bound,
            n_queries: proof.config.fri_config.n_queries as u64,
        },
    };

    let commitments: Vec<[u8; 32]> = proof
        .0
        .commitments
        .iter()
        .map(|commitment| commitment.0)
        .collect();

    let sampled_values: Vec<Vec<Vec<QM31>>> = proof
        .sampled_values
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|column| column.iter().copied().map(qm31_to_sol).collect())
                .collect()
        })
        .collect();

    let decommitments: Vec<Decommitment> = proof
        .0
        .decommitments
        .iter()
        .map(|decommitment| Decommitment {
            witness: decommitment
                .hash_witness
                .iter()
                .map(|hash| hash.0)
                .collect(),
            column_witness: decommitment.column_witness.iter().map(|v| v.0).collect(),
        })
        .collect();

    let first_layer = {
        let layer = &proof.0.fri_proof.first_layer;
        FriLayerProof {
            fri_witness: layer.fri_witness.iter().copied().map(qm31_to_sol).collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| h.0)
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|v| v.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: layer.commitment.0,
        }
    };

    let inner_layers: Vec<FriLayerProof> = proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .map(|layer| FriLayerProof {
            fri_witness: layer.fri_witness.iter().copied().map(qm31_to_sol).collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| h.0)
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|v| v.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: layer.commitment.0,
        })
        .collect();

    let fri_proof = FriProof {
        first_layer,
        inner_layers,
        last_layer_poly: {
            let mut coeffs = proof
                .clone()
                .0
                .fri_proof
                .last_layer_poly
                .into_ordered_coefficients();
            bit_reverse(&mut coeffs);
            coeffs.into_iter().map(qm31_to_sol).collect()
        },
    };

    let composition_coordinates: Vec<Vec<u32>> = composition_polynomial
        .into_coordinate_polys()
        .iter()
        .enumerate()
        .map(|(i, poly)| {
            let domain = CanonicCoset::new(poly.log_size()).circle_domain();
            let cpu_poly = poly.evaluate(domain).to_cpu().interpolate();
            let out: Vec<u32> = cpu_poly.coeffs.iter().map(|value| value.0).collect();
            println!(
                "Coordinate poly {}: log_size={}, coeffs.len()={}",
                i,
                poly.log_size(),
                out.len()
            );
            out
        })
        .collect();

    let composition_poly = CompositionPoly {
        coeffs0: composition_coordinates[0].clone(),
        coeffs1: composition_coordinates[1].clone(),
        coeffs2: composition_coordinates[2].clone(),
        coeffs3: composition_coordinates[3].clone(),
    };

    let queried_values: Vec<Vec<u32>> = proof
        .0
        .queried_values
        .iter()
        .map(|column| column.iter().map(|value| value.0).collect())
        .collect();

    Proof {
        config: sol_config,
        commitments,
        sampled_values,
        decommitments,
        queried_values,
        proof_of_work: proof.proof_of_work,
        fri_proof,
        composition_poly,
    }
}

fn component_info<C: FrameworkEval>(
    component: &FrameworkComponent<C>,
) -> ComponentInfo {
        ComponentInfo {
        max_constraint_log_degree_bound: component.max_constraint_log_degree_bound(),
        log_size: component.log_size(),
        mask_offsets: component
            .info
            .mask_offsets
            .0
            .iter()
            .map(|tree| {
                println!("[DEBUG] mask_offsets: tree.len() = {}", tree.len());
                tree.iter()
                    .map(|column| {
                        println!("[DEBUG] mask_offsets: column.len() = {}", column.len());
                        column.iter().map(|&offset| offset as i32).collect()
                    })
                    .collect()
            })
            .collect(),
        preprocessed_columns: {
            let cols: Vec<u64> = component
                .preprocessed_column_indices()
                .iter()
                .map(|&idx| idx as u64)
                .collect();
            println!("[DEBUG] preprocessed_columns.len() = {}", cols.len());
            cols
        },
    }
}

pub fn build_blake_verification_params(
    proof_data: &ProofData<KeccakMerkleHasher>,
) -> Result<VerificationParams, String> {
    let committed_hash_words = proof_data.commitment_stmt0.committed_hash_words();
    let blake_stmt0 = BlakeStatement0 {
        log_size: proof_data.commitment_stmt0.log_size,
    };
    let blake_log_sizes = proof_data.commitment_stmt0.log_sizes();

    let channel = &mut KeccakChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    commitment_scheme.commit(proof_data.proof.commitments[0], &blake_log_sizes[0], channel);
    proof_data.commitment_stmt0.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[1], &blake_log_sizes[1], channel);
    let all_elements = AllElements::draw(channel);
    proof_data.blake_stmt1.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[2], &blake_log_sizes[2], channel);

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &proof_data.blake_stmt1,
        committed_hash_words,
    );

    let mut component_params = Vec::new();
    let scheduler_info = component_info(&blake_components.scheduler_component);
    component_params.push(ComponentParams {
        log_size: blake_components.scheduler_component.log_size(),
        claimed_sum: qm31_to_sol(proof_data.blake_stmt1.scheduler_claimed_sum),
        info: scheduler_info,
    });

    for (round_component, claimed_sum) in blake_components
        .round_components
        .iter()
        .zip(proof_data.blake_stmt1.round_claimed_sums.iter().copied())
    {
        let info = component_info(round_component);
        component_params.push(ComponentParams {
            log_size: round_component.log_size(),
            claimed_sum: qm31_to_sol(claimed_sum),
            info,
        });
    }

    let xor12_info = component_info(&blake_components.xor12);
    component_params.push(ComponentParams {
        log_size: blake_components.xor12.log_size(),
        claimed_sum: qm31_to_sol(proof_data.blake_stmt1.xor12_claimed_sum),
        info: xor12_info,
    });

    let xor9_info = component_info(&blake_components.xor9);
    component_params.push(ComponentParams {
        log_size: blake_components.xor9.log_size(),
        claimed_sum: qm31_to_sol(proof_data.blake_stmt1.xor9_claimed_sum),
        info: xor9_info,
    });

    let xor8_info = component_info(&blake_components.xor8);
    component_params.push(ComponentParams {
        log_size: blake_components.xor8.log_size(),
        claimed_sum: qm31_to_sol(proof_data.blake_stmt1.xor8_claimed_sum),
        info: xor8_info,
    });

    let xor7_info = component_info(&blake_components.xor7);
    component_params.push(ComponentParams {
        log_size: blake_components.xor7.log_size(),
        claimed_sum: qm31_to_sol(proof_data.blake_stmt1.xor7_claimed_sum),
        info: xor7_info,
    });

    let xor4_info = component_info(&blake_components.xor4);
    component_params.push(ComponentParams {
        log_size: blake_components.xor4.log_size(),
        claimed_sum: qm31_to_sol(proof_data.blake_stmt1.xor4_claimed_sum),
        info: xor4_info,
    });

    let n_preprocessed_columns = commitment_scheme.trees[0].column_log_sizes.len();
    let components_vec: Vec<&dyn Component> = blake_components.as_components_vec();
    let components = Components {
        components: components_vec,
        n_preprocessed_columns,
    };

    Ok(VerificationParams {
        component_params,
        n_preprocessed_columns: n_preprocessed_columns as u64,
        components_composition_log_degree_bound: components.composition_log_degree_bound(),
    })
}

fn validate_sample_shape(
    proof_data: &ProofData<KeccakMerkleHasher>,
    verification_params: &VerificationParams,
) -> Result<(), String> {
    let committed_hash_words = proof_data.commitment_stmt0.committed_hash_words();
    let blake_stmt0 = BlakeStatement0 {
        log_size: proof_data.commitment_stmt0.log_size,
    };
    let blake_log_sizes = proof_data.commitment_stmt0.log_sizes();

    let channel = &mut KeccakChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    commitment_scheme.commit(proof_data.proof.commitments[0], &blake_log_sizes[0], channel);
    proof_data.commitment_stmt0.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[1], &blake_log_sizes[1], channel);
    let all_elements = AllElements::draw(channel);
    proof_data.blake_stmt1.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[2], &blake_log_sizes[2], channel);

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &proof_data.blake_stmt1,
        committed_hash_words,
    );

    let components_vec: Vec<&dyn Component> = blake_components.as_components_vec();
    let components = Components {
        components: components_vec,
        n_preprocessed_columns: verification_params.n_preprocessed_columns as usize,
    };

    let _random_coeff = channel.draw_secure_felt();
    commitment_scheme.commit(
        *proof_data
            .proof
            .commitments
            .last()
            .ok_or_else(|| "Missing composition commitment".to_string())?,
        &[components.composition_log_degree_bound(); SECURE_EXTENSION_DEGREE],
        channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let mut sample_points = components.mask_points(oods_point);
    sample_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

    if sample_points.len() != proof_data.proof.sampled_values.len() {
        return Err(format!(
            "Tree count mismatch in sampled values: expected {}, got {}",
            sample_points.len(),
            proof_data.proof.sampled_values.len()
        ));
    }

    for (tree_idx, (expected_tree, proof_tree)) in sample_points
        .iter()
        .zip(proof_data.proof.sampled_values.iter())
        .enumerate()
    {
        if expected_tree.len() != proof_tree.len() {
            return Err(format!(
                "Column count mismatch in tree {tree_idx}: expected {}, got {}",
                expected_tree.len(),
                proof_tree.len()
            ));
        }

        for (col_idx, (expected_col, proof_col)) in
            expected_tree.iter().zip(proof_tree.iter()).enumerate()
        {
            if expected_col.len() != proof_col.len() {
                return Err(format!(
                    "Sample count mismatch in tree {tree_idx}, column {col_idx}: expected {}, got {}",
                    expected_col.len(),
                    proof_col.len()
                ));
            }
        }
    }

    Ok(())
}

fn blake_transcript_digest(proof_data: &ProofData<KeccakMerkleHasher>) -> [u8; 32] {
    let blake_log_sizes = proof_data.commitment_stmt0.log_sizes();
    let channel = &mut KeccakChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    commitment_scheme.commit(proof_data.proof.commitments[0], &blake_log_sizes[0], channel);
    proof_data.commitment_stmt0.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[1], &blake_log_sizes[1], channel);
    let _ = AllElements::draw(channel);
    proof_data.blake_stmt1.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[2], &blake_log_sizes[2], channel);

    channel.digest().0
}

pub fn build_blake_onchain_input(
    proof_data: &ProofData<KeccakMerkleHasher>,
) -> Result<OnchainVerifyInput, String> {
    let verification_params = build_blake_verification_params(proof_data)?;
    validate_sample_shape(proof_data, &verification_params)?;
    let proof = convert_stark_proof_to_solidity(
        proof_data.proof.clone(),
        proof_data.composition_polynomial.clone(),
    );

    if proof_data.proof.commitments.is_empty() {
        return Err("Inconsistent proof: no commitments".to_string());
    }

    // The Solidity verifier adds the composition tree via commit() during verification.
    // Pass only trace trees here (all commitments except the last one).
    let tree_roots: Vec<[u8; 32]> = proof_data
        .proof
        .commitments
        .iter()
        .take(proof_data.proof.commitments.len() - 1)
        .map(|c| c.0)
        .collect();

    let blowup = proof_data.proof.config.fri_config.log_blowup_factor;
    let mut tree_column_log_sizes: Vec<Vec<u32>> = proof_data
        .commitment_stmt0
        .log_sizes()
        .iter()
        .map(|tree_sizes| tree_sizes.iter().map(|&v| v + blowup).collect())
        .collect();

    if proof_data.proof.sampled_values.len() != proof_data.proof.commitments.len() {
        return Err(format!(
            "Inconsistent proof: sampled_values trees ({}) != commitments ({})",
            proof_data.proof.sampled_values.len(),
            proof_data.proof.commitments.len()
        ));
    }
    if proof_data.proof.queried_values.len() != proof_data.proof.commitments.len() {
        return Err(format!(
            "Inconsistent proof: queried_values trees ({}) != commitments ({})",
            proof_data.proof.queried_values.len(),
            proof_data.proof.commitments.len()
        ));
    }

    if tree_column_log_sizes.len() != tree_roots.len() {
        return Err(format!(
            "Inconsistent input: tree_column_log_sizes trees ({}) != tree_roots ({})",
            tree_column_log_sizes.len(),
            tree_roots.len()
        ));
    }

    Ok(OnchainVerifyInput {
        proof,
        verification_params,
        tree_roots,
        tree_column_log_sizes,
        digest: blake_transcript_digest(proof_data),
        n_draws: 0,
    })
}

#[cfg(feature = "onchain-rpc")]
mod rpc {
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, U256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionRequest,
        sol,
        sol_types::SolCall,
    };

    use super::{CM31, ComponentInfo, ComponentParams, Config, Decommitment, FriConfig, FriLayerProof, FriProof, OnchainVerifyInput, Proof, QM31, VerificationParams};

    sol! {
        struct QM31Abi {
            CM31Abi first;
            CM31Abi second;
        }
        struct CM31Abi {
            uint32 real;
            uint32 imag;
        }
        struct ConfigAbi {
            uint32 powBits;
            FriConfigAbi friConfig;
        }
        struct FriConfigAbi {
            uint32 logBlowupFactor;
            uint32 logLastLayerDegreeBound;
            uint256 nQueries;
        }
        struct DecommitmentAbi {
            bytes32[] witness;
            uint32[] columnWitness;
        }
        struct FriLayerProofAbi {
            QM31Abi[] friWitness;
            bytes decommitment;
            bytes32 commitment;
        }
        struct FriProofAbi {
            FriLayerProofAbi firstLayer;
            FriLayerProofAbi[] innerLayers;
            QM31Abi[] lastLayerPoly;
        }
        struct CompositionPolyAbi {
            uint32[] coeffs0;
            uint32[] coeffs1;
            uint32[] coeffs2;
            uint32[] coeffs3;
        }
        struct ProofAbi {
            ConfigAbi config;
            bytes32[] commitments;
            QM31Abi[][][] sampledValues;
            DecommitmentAbi[] decommitments;
            uint32[][] queriedValues;
            uint64 proofOfWork;
            FriProofAbi friProof;
            CompositionPolyAbi compositionPoly;
        }
        struct ComponentInfoAbi {
            uint32 maxConstraintLogDegreeBound;
            uint32 logSize;
            int32[][][] maskOffsets;
            uint256[] preprocessedColumns;
        }
        struct ComponentParamsAbi {
            uint32 logSize;
            QM31Abi claimedSum;
            ComponentInfoAbi info;
        }
        struct VerificationParamsAbi {
            ComponentParamsAbi[] componentParams;
            uint256 nPreprocessedColumns;
            uint32 componentsCompositionLogDegreeBound;
        }
        interface IStwoVerifier {
            function verify(
                ProofAbi calldata proof,
                VerificationParamsAbi calldata params,
                bytes32[] memory treeRoots,
                uint32[][] memory treeColumnLogSizes,
                bytes32 digest,
                uint32 nDraws
            ) external view returns (bool);

            function debugOodsVerification(
                ProofAbi calldata proof,
                VerificationParamsAbi calldata params,
                bytes32[] memory treeRoots,
                uint32[][] memory treeColumnLogSizes,
                bytes32 digest,
                uint32 nDraws
            ) external returns (bool doesMatch, QM31Abi memory expectedOods, QM31Abi memory computedOods);
        }

    }

    fn map_qm31(v: &QM31) -> QM31Abi {
        QM31Abi {
            first: CM31Abi {
                real: v.first.real,
                imag: v.first.imag,
            },
            second: CM31Abi {
                real: v.second.real,
                imag: v.second.imag,
            },
        }
    }

    fn map_config(v: &Config) -> ConfigAbi {
        ConfigAbi {
            powBits: v.pow_bits,
            friConfig: FriConfigAbi {
                logBlowupFactor: v.fri_config.log_blowup_factor,
                logLastLayerDegreeBound: v.fri_config.log_last_layer_degree_bound,
                nQueries: U256::from(v.fri_config.n_queries),
            },
        }
    }

    fn map_decommitment(v: &Decommitment) -> DecommitmentAbi {
        DecommitmentAbi {
            witness: v.witness.iter().copied().map(FixedBytes::from).collect(),
            columnWitness: v.column_witness.clone(),
        }
    }

    fn map_fri_layer(v: &FriLayerProof) -> FriLayerProofAbi {
        FriLayerProofAbi {
            friWitness: v.fri_witness.iter().map(map_qm31).collect(),
            decommitment: Bytes::from(v.decommitment.clone()),
            commitment: FixedBytes::from(v.commitment),
        }
    }

    fn map_fri(v: &FriProof) -> FriProofAbi {
        FriProofAbi {
            firstLayer: map_fri_layer(&v.first_layer),
            innerLayers: v.inner_layers.iter().map(map_fri_layer).collect(),
            lastLayerPoly: v.last_layer_poly.iter().map(map_qm31).collect(),
        }
    }

    fn map_component_info(v: &ComponentInfo) -> ComponentInfoAbi {
        ComponentInfoAbi {
            maxConstraintLogDegreeBound: v.max_constraint_log_degree_bound,
            logSize: v.log_size,
            maskOffsets: v.mask_offsets.clone(),
            preprocessedColumns: v.preprocessed_columns.iter().copied().map(U256::from).collect(),
        }
    }

    fn map_component(v: &ComponentParams) -> ComponentParamsAbi {
        ComponentParamsAbi {
            logSize: v.log_size,
            claimedSum: map_qm31(&v.claimed_sum),
            info: map_component_info(&v.info),
        }
    }

    fn map_proof(v: &Proof) -> ProofAbi {
        ProofAbi {
            config: map_config(&v.config),
            commitments: v.commitments.iter().copied().map(FixedBytes::from).collect(),
            sampledValues: v
                .sampled_values
                .iter()
                .map(|tree| {
                    tree.iter()
                        .map(|column| column.iter().map(map_qm31).collect())
                        .collect()
                })
                .collect(),
            decommitments: v.decommitments.iter().map(map_decommitment).collect(),
            queriedValues: v.queried_values.clone(),
            proofOfWork: v.proof_of_work,
            friProof: map_fri(&v.fri_proof),
            compositionPoly: CompositionPolyAbi {
                coeffs0: v.composition_poly.coeffs0.clone(),
                coeffs1: v.composition_poly.coeffs1.clone(),
                coeffs2: v.composition_poly.coeffs2.clone(),
                coeffs3: v.composition_poly.coeffs3.clone(),
            },
        }
    }

    fn map_params(v: &VerificationParams) -> VerificationParamsAbi {
        VerificationParamsAbi {
            componentParams: v.component_params.iter().map(map_component).collect(),
            nPreprocessedColumns: U256::from(v.n_preprocessed_columns),
            componentsCompositionLogDegreeBound: v.components_composition_log_degree_bound,
        }
    }

    pub fn verify_onchain_call(
        rpc_url: &str,
        verifier_address: Address,
        input: &OnchainVerifyInput,
    ) -> Result<bool, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create Tokio runtime: {e}"))?;

        let proof = map_proof(&input.proof);
        let params = map_params(&input.verification_params);
        let tree_roots: Vec<FixedBytes<32>> =
            input.tree_roots.iter().copied().map(FixedBytes::from).collect();
        let digest = FixedBytes::from(input.digest);
        let tree_column_log_sizes = input.tree_column_log_sizes.clone();
        let n_draws = input.n_draws;

        runtime.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(
                rpc_url
                    .parse()
                    .map_err(|e| format!("Invalid RPC URL: {e}"))?,
            );

            let call_data = IStwoVerifier::verifyCall {
                proof,
                params,
                treeRoots: tree_roots,
                treeColumnLogSizes: tree_column_log_sizes,
                digest,
                nDraws: n_draws,
            };

            let tx = TransactionRequest::default()
                .to(verifier_address)
                .input(call_data.abi_encode().into());

            let raw = provider
                .call(tx)
                .await
                .map_err(|err| format!("Verifier contract call reverted: {err}"))?;

            IStwoVerifier::verifyCall::abi_decode_returns(&raw)
                .map_err(|e| format!("Failed to decode verify() return value: {e}"))
        })
    }
}

#[cfg(feature = "onchain-rpc")]
pub use rpc::{verify_onchain_call};
