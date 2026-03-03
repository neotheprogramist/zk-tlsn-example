use std::collections::HashMap;

use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall,
};
use itertools::chain;
use stwo::{
    core::{
        air::{Component, Components},
        channel::{Channel, KeccakChannel, MerkleChannel},
        circle::CirclePoint,
        fields::{m31::BaseField, qm31::SecureField},
        pcs::{CommitmentSchemeVerifier, TreeVec},
        poly::circle::CanonicCoset,
        utils::bit_reverse,
        vcs::{
            keccak_hash::KeccakHash,
            keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher},
        },
    },
    prover::{backend::simd::SimdBackend, poly::circle::SecureCirclePoly},
};
use stwo_constraint_framework::{FrameworkEval, TraceLocationAllocator};

use crate::{
    blake3::{
        AllElements, BlakeComponentsForIntegration, BlakeStatement0, preprocessed_columns::XorTable,
    },
    combined_circuit::{CommitmentStatement0, WithdrawProof},
    merkle_membership::{
        MerkleMembershipComponent, MerkleMembershipEval, MerkleStatement0,
        merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
        merkle_is_step_column_id,
    },
    poseidon_chain::{
        ChainStatement0, PoseidonChainComponent, PoseidonChainEval, is_active_column_id,
        is_last_column_id, is_step_column_id,
    },
    relations::{LeafRelation, RootRelation},
    scheduler::{
        PrivacyPoolSchedulerComponent, PrivacyPoolSchedulerEval, SchedulerStatement0,
        is_first_column_id as scheduler_is_first_column_id,
    },
};

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

fn extract_composition_oods_eval(
    proof: &stwo::core::proof::StarkProof<KeccakMerkleHasher>,
) -> Option<SecureField> {
    let [.., composition_mask] = &**proof.sampled_values else {
        return None;
    };
    let coordinate_evals = composition_mask
        .iter()
        .map(|columns| {
            let &[eval] = &columns[..] else {
                return None;
            };
            Some(eval)
        })
        .collect::<Option<Vec<_>>>()?
        .try_into()
        .ok()?;
    Some(SecureField::from_partial_evals(coordinate_evals))
}

fn qm31(value: SecureField) -> QM31 {
    QM31 {
        first: CM31 {
            real: value.0.0.0,
            imag: value.0.1.0,
        },
        second: CM31 {
            real: value.1.0.0,
            imag: value.1.1.0,
        },
    }
}

fn encode_decommitment_packed(hash_witness: &[FixedBytes<32>], column_witness: &[u32]) -> Bytes {
    let mut encoded = Vec::new();

    let length_bytes: [u8; 32] = U256::from(hash_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&length_bytes);

    for witness in hash_witness {
        encoded.extend_from_slice(witness.as_slice());
    }

    let column_length_bytes: [u8; 32] = U256::from(column_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&column_length_bytes);

    for &value in column_witness {
        encoded.extend_from_slice(&value.to_be_bytes());
    }

    Bytes::from(encoded)
}

pub fn convert_to_solidity_proof(
    proof: &stwo::core::proof::StarkProof<KeccakMerkleHasher>,
    composition_polynomial: &SecureCirclePoly<SimdBackend>,
) -> Proof {
    let sol_config = Config {
        powBits: proof.config.pow_bits,
        friConfig: FriConfig {
            logBlowupFactor: proof.config.fri_config.log_blowup_factor,
            logLastLayerDegreeBound: proof.config.fri_config.log_last_layer_degree_bound,
            nQueries: U256::from(proof.config.fri_config.n_queries),
        },
    };

    let commitments: Vec<FixedBytes<32>> = proof
        .0
        .commitments
        .iter()
        .map(|commitment| FixedBytes::from(commitment.0))
        .collect();

    let sampled_values: Vec<Vec<Vec<QM31>>> = proof
        .sampled_values
        .iter()
        .map(|column| {
            column
                .iter()
                .map(|row| row.iter().copied().map(qm31).collect())
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
                .map(|hash| FixedBytes::from(hash.0))
                .collect(),
            columnWitness: decommitment
                .column_witness
                .iter()
                .map(|value| value.0)
                .collect(),
        })
        .collect();

    let first_layer = {
        let layer = &proof.0.fri_proof.first_layer;
        FriLayerProof {
            friWitness: layer.fri_witness.iter().copied().map(qm31).collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|hash| FixedBytes::from(hash.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|value| value.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        }
    };

    let inner_layers: Vec<FriLayerProof> = proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .map(|layer| FriLayerProof {
            friWitness: layer.fri_witness.iter().copied().map(qm31).collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|hash| FixedBytes::from(hash.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|value| value.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        })
        .collect();

    let mut last_layer_coeffs = proof
        .0
        .fri_proof
        .last_layer_poly
        .clone()
        .into_ordered_coefficients();
    bit_reverse(&mut last_layer_coeffs);

    let fri_proof = FriProof {
        firstLayer: first_layer,
        innerLayers: inner_layers,
        lastLayerPoly: last_layer_coeffs.into_iter().map(qm31).collect(),
    };

    let composition_coordinates: Vec<Vec<u32>> = composition_polynomial
        .clone()
        .into_coordinate_polys()
        .iter()
        .map(|poly| {
            let domain = CanonicCoset::new(poly.log_size()).circle_domain();
            let cpu_poly = poly.evaluate(domain).to_cpu().interpolate();
            cpu_poly.coeffs.iter().map(|value| value.0).collect()
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
        sampledValues: sampled_values,
        decommitments,
        queriedValues: queried_values,
        proofOfWork: proof.proof_of_work,
        friProof: fri_proof,
        compositionPoly: composition_poly,
    }
}

fn full_log_sizes(commitment_stmt0: &CommitmentStatement0, log_size: u32) -> TreeVec<Vec<u32>> {
    let blake_log_sizes = commitment_stmt0.log_sizes();
    let chain_log_sizes = ChainStatement0 { log_size }.log_sizes();
    let merkle_log_sizes = MerkleStatement0 { log_size }.log_sizes();
    let scheduler_log_sizes = SchedulerStatement0 { log_size }.log_sizes();

    let mut merged = blake_log_sizes.clone();
    merged[0].extend(chain_log_sizes[0].iter().copied());
    merged[0].extend(merkle_log_sizes[0].iter().copied());
    merged[0].extend(scheduler_log_sizes[0].iter().copied());
    merged[1].extend(chain_log_sizes[1].iter().copied());
    merged[1].extend(merkle_log_sizes[1].iter().copied());
    merged[1].extend(scheduler_log_sizes[1].iter().copied());
    merged[2].extend(chain_log_sizes[2].iter().copied());
    merged[2].extend(merkle_log_sizes[2].iter().copied());
    merged[2].extend(scheduler_log_sizes[2].iter().copied());
    merged
}

fn ordered_preprocessed_ids(log_size: u32, merkle_depth: usize) -> Vec<String> {
    let mut ids = vec![
        XorTable::new(12, 4, 0).id().id,
        XorTable::new(12, 4, 1).id().id,
        XorTable::new(12, 4, 2).id().id,
        XorTable::new(9, 2, 0).id().id,
        XorTable::new(9, 2, 1).id().id,
        XorTable::new(9, 2, 2).id().id,
        XorTable::new(8, 2, 0).id().id,
        XorTable::new(8, 2, 1).id().id,
        XorTable::new(8, 2, 2).id().id,
        XorTable::new(7, 2, 0).id().id,
        XorTable::new(7, 2, 1).id().id,
        XorTable::new(7, 2, 2).id().id,
        XorTable::new(4, 0, 0).id().id,
        XorTable::new(4, 0, 1).id().id,
        XorTable::new(4, 0, 2).id().id,
    ];

    ids.extend([
        is_active_column_id(log_size, "deposit").id,
        is_step_column_id(log_size, "deposit").id,
        is_last_column_id(log_size, "deposit").id,
        merkle_is_active_column_id(log_size, merkle_depth).id,
        merkle_is_step_column_id(log_size, merkle_depth).id,
        merkle_is_first_column_id(log_size, merkle_depth).id,
        merkle_is_last_column_id(log_size, merkle_depth).id,
        scheduler_is_first_column_id(log_size).id,
    ]);
    ids
}

fn component_info<C: stwo_constraint_framework::FrameworkEval>(
    component: &stwo_constraint_framework::FrameworkComponent<C>,
    preprocessed_index: &HashMap<String, usize>,
) -> Result<ComponentInfo, String> {
    let preprocessed_columns: Result<Vec<U256>, String> = component
        .info
        .preprocessed_columns
        .iter()
        .map(|column| {
            preprocessed_index
                .get(&column.id)
                .copied()
                .map(U256::from)
                .ok_or_else(|| format!("Missing preprocessed column id mapping: {}", column.id))
        })
        .collect();

    Ok(ComponentInfo {
        maxConstraintLogDegreeBound: component.max_constraint_log_degree_bound(),
        logSize: component.log_size(),
        maskOffsets: component
            .info
            .mask_offsets
            .0
            .iter()
            .map(|tree| {
                tree.iter()
                    .map(|column| column.iter().map(|&offset| offset as i32).collect())
                    .collect()
            })
            .collect(),
        preprocessedColumns: preprocessed_columns?,
    })
}

pub fn build_onchain_verification_input(
    proof_data: &WithdrawProof<KeccakMerkleHasher>,
) -> Result<OnchainVerificationInput, String> {
    let full_log_sizes = full_log_sizes(&proof_data.commitment_stmt0, proof_data.log_size);
    let n_preprocessed_columns = full_log_sizes[0].len();

    let mut channel = KeccakChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    commitment_scheme.commit(
        proof_data.proof.commitments[0],
        &full_log_sizes[0],
        &mut channel,
    );
    proof_data.commitment_stmt0.mix_into(&mut channel);
    commitment_scheme.commit(
        proof_data.proof.commitments[1],
        &full_log_sizes[1],
        &mut channel,
    );

    let all_elements = AllElements::draw(&mut channel);
    let leaf_relation = LeafRelation::draw(&mut channel);
    let root_relation = RootRelation::draw(&mut channel);
    proof_data.blake_stmt1.mix_into(&mut channel);

    commitment_scheme.commit(
        proof_data.proof.commitments[2],
        &full_log_sizes[2],
        &mut channel,
    );

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_stmt0 = BlakeStatement0 {
        log_size: proof_data.log_size,
    };
    let committed_hash_words = proof_data.commitment_stmt0.committed_hash_words();

    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &proof_data.blake_stmt1,
        committed_hash_words,
    );

    let deposit_component = PoseidonChainComponent::new(
        &mut tree_span_provider,
        PoseidonChainEval {
            log_n_rows: proof_data.log_size,
            is_active_id: is_active_column_id(proof_data.log_size, "deposit"),
            is_step_id: is_step_column_id(proof_data.log_size, "deposit"),
            is_last_id: is_last_column_id(proof_data.log_size, "deposit"),
            leaf_relation: leaf_relation.clone(),
            leaf_multiplicity: 2,
            claimed_sum: proof_data.deposit_claimed_sum,
        },
        proof_data.deposit_claimed_sum,
    );

    let merkle_component = MerkleMembershipComponent::new(
        &mut tree_span_provider,
        MerkleMembershipEval {
            log_n_rows: proof_data.log_size,
            depth: proof_data.merkle_depth,
            is_active_id: merkle_is_active_column_id(proof_data.log_size, proof_data.merkle_depth),
            is_step_id: merkle_is_step_column_id(proof_data.log_size, proof_data.merkle_depth),
            is_first_id: merkle_is_first_column_id(proof_data.log_size, proof_data.merkle_depth),
            is_last_id: merkle_is_last_column_id(proof_data.log_size, proof_data.merkle_depth),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            claimed_sum: proof_data.merkle_claimed_sum,
        },
        proof_data.merkle_claimed_sum,
    );

    let scheduler_component = PrivacyPoolSchedulerComponent::new(
        &mut tree_span_provider,
        PrivacyPoolSchedulerEval {
            log_n_rows: proof_data.log_size,
            is_first_id: scheduler_is_first_column_id(proof_data.log_size),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            amount: proof_data.amount,
            refund_commitment_hash: BaseField::from_u32_unchecked(0),
            claimed_sum: proof_data.scheduler_claimed_sum,
        },
        proof_data.scheduler_claimed_sum,
    );

    let ordered_ids = ordered_preprocessed_ids(proof_data.log_size, proof_data.merkle_depth);
    let preprocessed_index: HashMap<String, usize> = ordered_ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect();

    let mut component_params = Vec::new();

    let scheduler_info =
        component_info(&blake_components.scheduler_component, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: blake_components.scheduler_component.log_size(),
        claimedSum: qm31(proof_data.blake_stmt1.scheduler_claimed_sum),
        info: scheduler_info,
    });

    for (round_component, claimed_sum) in blake_components
        .round_components
        .iter()
        .zip(proof_data.blake_stmt1.round_claimed_sums.iter().copied())
    {
        let info = component_info(round_component, &preprocessed_index)?;
        component_params.push(ComponentParams {
            logSize: round_component.log_size(),
            claimedSum: qm31(claimed_sum),
            info,
        });
    }

    let xor12_info = component_info(&blake_components.xor12, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: blake_components.xor12.log_size(),
        claimedSum: qm31(proof_data.blake_stmt1.xor12_claimed_sum),
        info: xor12_info,
    });

    let xor9_info = component_info(&blake_components.xor9, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: blake_components.xor9.log_size(),
        claimedSum: qm31(proof_data.blake_stmt1.xor9_claimed_sum),
        info: xor9_info,
    });

    let xor8_info = component_info(&blake_components.xor8, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: blake_components.xor8.log_size(),
        claimedSum: qm31(proof_data.blake_stmt1.xor8_claimed_sum),
        info: xor8_info,
    });

    let xor7_info = component_info(&blake_components.xor7, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: blake_components.xor7.log_size(),
        claimedSum: qm31(proof_data.blake_stmt1.xor7_claimed_sum),
        info: xor7_info,
    });

    let xor4_info = component_info(&blake_components.xor4, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: blake_components.xor4.log_size(),
        claimedSum: qm31(proof_data.blake_stmt1.xor4_claimed_sum),
        info: xor4_info,
    });

    let deposit_info = component_info(&deposit_component, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: deposit_component.log_size(),
        claimedSum: qm31(proof_data.deposit_claimed_sum),
        info: deposit_info,
    });

    let merkle_info = component_info(&merkle_component, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: merkle_component.log_size(),
        claimedSum: qm31(proof_data.merkle_claimed_sum),
        info: merkle_info,
    });

    let scheduler_component_info = component_info(&scheduler_component, &preprocessed_index)?;
    component_params.push(ComponentParams {
        logSize: scheduler_component.log_size(),
        claimedSum: qm31(proof_data.scheduler_claimed_sum),
        info: scheduler_component_info,
    });

    let components_vec: Vec<&dyn Component> = chain![
        blake_components
            .as_components_vec()
            .into_iter()
            .map(|component| component as &dyn Component),
        [&deposit_component as &dyn Component],
        [&merkle_component as &dyn Component],
        [&scheduler_component as &dyn Component],
    ]
    .collect();

    let components = Components {
        components: components_vec,
        n_preprocessed_columns,
    };

    let verification_params = VerificationParams {
        componentParams: component_params,
        nPreprocessedColumns: U256::from(n_preprocessed_columns),
        componentsCompositionLogDegreeBound: components.composition_log_degree_bound(),
    };

    let tree_roots: Vec<FixedBytes<32>> = proof_data
        .proof
        .commitments
        .iter()
        .take(full_log_sizes.len())
        .map(|root| FixedBytes::from(root.0))
        .collect();

    let tree_column_log_sizes: Vec<Vec<u32>> = full_log_sizes
        .iter()
        .map(|tree_sizes| {
            tree_sizes
                .iter()
                .map(|&log_size| log_size + proof_data.proof.config.fri_config.log_blowup_factor)
                .collect()
        })
        .collect();

    let digest = KeccakHash(proof_data.transcript_digest);
    let composition_commitment = *proof_data
        .proof
        .commitments
        .last()
        .ok_or_else(|| "Missing composition commitment".to_string())?;
    let extracted_oods = extract_composition_oods_eval(&proof_data.proof)
        .ok_or_else(|| "Unexpected sampled_values structure in proof".to_string())?;
    let mut oods_channel = KeccakChannel::default();
    oods_channel.update_digest(digest);
    for _ in 0..proof_data.transcript_n_draws {
        let _ = oods_channel.draw_u32s();
    }
    let _random_coeff = oods_channel.draw_secure_felt();
    KeccakMerkleChannel::mix_root(&mut oods_channel, composition_commitment);
    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut oods_channel);
    let expected_oods = proof_data.composition_polynomial.eval_at_point(oods_point);
    if extracted_oods != expected_oods {
        return Err(format!(
            "Local OODS mismatch before contract call: extracted={extracted_oods:?}, expected={expected_oods:?}"
        ));
    }

    Ok(OnchainVerificationInput {
        proof: convert_to_solidity_proof(&proof_data.proof, &proof_data.composition_polynomial),
        params: verification_params,
        tree_roots,
        tree_column_log_sizes,
        digest: FixedBytes::from(digest.0),
        n_draws: proof_data.transcript_n_draws,
    })
}

pub fn verify_onchain_call(
    rpc_url: &str,
    verifier_address: Address,
    input: OnchainVerificationInput,
) -> Result<bool, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create Tokio runtime: {e}"))?;

    runtime.block_on(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let call_data = IStwoVerifier::verifyCall {
            proof: input.proof,
            params: input.params,
            treeRoots: input.tree_roots,
            treeColumnLogSizes: input.tree_column_log_sizes,
            digest: input.digest,
            nDraws: input.n_draws,
        };

        let tx = TransactionRequest::default()
            .to(verifier_address)
            .input(call_data.abi_encode().into());

        let raw = provider
            .call(tx)
            .await
            .map_err(|err| format!("Verifier contract call reverted: {err}"))?;

        let decoded = IStwoVerifier::verifyCall::abi_decode_returns(&raw)
            .map_err(|e| format!("Failed to decode verify() return value: {e}"))?;

        Ok(decoded)
    })
}

pub fn build_verify_calldata(input: &OnchainVerificationInput) -> Bytes {
    IStwoVerifier::verifyCall {
        proof: input.proof.clone(),
        params: input.params.clone(),
        treeRoots: input.tree_roots.clone(),
        treeColumnLogSizes: input.tree_column_log_sizes.clone(),
        digest: input.digest,
        nDraws: input.n_draws,
    }
    .abi_encode()
    .into()
}

pub fn simulate_withdraw_with_proof_call(
    rpc_url: &str,
    pool_address: Address,
    root: U256,
    nullifier: U256,
    token: Address,
    amount: U256,
    recipient: Address,
    verify_input: &OnchainVerificationInput,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create Tokio runtime: {e}"))?;

    let verify_calldata = build_verify_calldata(verify_input);

    runtime.block_on(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let call_data = IPrivacyPool::withdrawCall {
            root,
            nullifier,
            token,
            amount,
            recipient,
            verifyCalldata: verify_calldata,
        };

        let tx = TransactionRequest::default()
            .to(pool_address)
            .input(call_data.abi_encode().into());

        provider
            .call(tx)
            .await
            .map_err(|err| format!("PrivacyPool withdraw simulation reverted: {err}"))?;

        Ok(())
    })
}
