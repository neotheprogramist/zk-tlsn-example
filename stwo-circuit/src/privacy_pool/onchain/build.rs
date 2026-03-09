use std::collections::HashMap;

use alloy::primitives::{FixedBytes, U256};
use itertools::chain;
use stwo::core::{
    air::{Component, Components},
    channel::{Channel, KeccakChannel, MerkleChannel},
    circle::CirclePoint,
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, TreeVec},
    vcs::{keccak_hash::KeccakHash, keccak_merkle::KeccakMerkleChannel},
};
use stwo_constraint_framework::{FrameworkEval, TraceLocationAllocator};

use crate::{
    CommitmentStatement0,
    blake3::{
        AllElements, BlakeComponentsForIntegration, BlakeStatement0, preprocessed_columns::XorTable,
    },
    withdraw_circuit::WithdrawProof,
    privacy_pool::{
        merkle_membership::{
            MerkleMembershipComponent, MerkleMembershipEval, MerkleStatement0,
            merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
            merkle_is_step_column_id,
        },
        onchain::{
            convert::{convert_to_solidity_proof, extract_composition_oods_eval, qm31},
            types::{ComponentInfo, ComponentParams, OnchainVerificationInput, VerificationParams},
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
    },
};

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

fn component_info<C: FrameworkEval>(
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
    proof_data: &WithdrawProof<stwo::core::vcs::keccak_merkle::KeccakMerkleHasher>,
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
            refund_commitment_hash: proof_data.refund_commitment_hash,
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
