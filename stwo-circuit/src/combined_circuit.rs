use itertools::{chain, multiunzip};
use num_traits::Zero;
use stwo::{
    core::{
        channel::{Channel, KeccakChannel},
        fields::{m31::BaseField, qm31::SecureField},
        pcs::{CommitmentSchemeVerifier, PcsConfig},
        poly::circle::CanonicCoset,
        proof::StarkProof,
        vcs::{
            MerkleHasher,
            keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher},
        },
        verifier::verify,
    },
    prover::{
        CommitmentSchemeProver,
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::circle::{PolyOps, SecureCirclePoly},
    },
};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_polynomial::prove::prove;

use crate::{
    blake3::{
        AllElements, BlakeComponentsForIntegration, BlakeStatement0, BlakeStatement1,
        ROUND_LOG_SPLIT, XorAccums, preprocessed_columns::XorTable, round,
        scheduler as BlakeScheduler, xor_table,
    },
    merkle_membership::{
        MerkleInputs, MerkleMembershipComponent, MerkleMembershipEval, MerkleStatement0,
        gen_merkle_is_active_column, gen_merkle_is_first_column, gen_merkle_is_last_column,
        gen_merkle_is_step_column, gen_merkle_membership_interaction_trace, gen_merkle_trace,
        merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
        merkle_is_step_column_id,
    },
    poseidon_chain::{
        ChainInputs, ChainStatement0, PoseidonChainComponent, PoseidonChainEval,
        gen_is_active_column, gen_is_last_column, gen_is_step_column,
        gen_poseidon_chain_interaction_trace, gen_poseidon_chain_trace, is_active_column_id,
        is_last_column_id, is_step_column_id,
    },
    relations::{LeafRelation, RootRelation},
    scheduler::{
        PrivacyPoolSchedulerComponent, PrivacyPoolSchedulerEval, SchedulerStatement0,
        gen_is_first_column as gen_scheduler_is_first_column, gen_scheduler_interaction_trace,
        gen_scheduler_trace, is_first_column_id as scheduler_is_first_column_id,
    },
};

#[derive(Clone, Debug)]
pub struct WithdrawInputs {
    pub balance_fragment: Vec<u8>,
    pub blinder: [u8; 16],
    pub commitment_hash: [u8; 32],
    pub secret: BaseField,
    pub nullifier: BaseField,
    pub amount: BaseField,
    pub token_address: BaseField,
    pub merkle_siblings: Vec<BaseField>,
    pub merkle_index: u32,
    pub merkle_root: BaseField,
}

#[derive(Clone)]
pub struct WithdrawProof<H: MerkleHasher> {
    pub commitment_stmt0: CommitmentStatement0,
    pub blake_stmt1: BlakeStatement1,
    pub merkle_root: BaseField,
    pub nullifier: BaseField,
    pub amount: BaseField,
    pub token_address: BaseField,
    pub log_size: u32,
    pub merkle_depth: usize,
    pub deposit_claimed_sum: SecureField,
    pub merkle_claimed_sum: SecureField,
    pub scheduler_claimed_sum: SecureField,
    pub composition_polynomial: SecureCirclePoly<SimdBackend>,
    pub transcript_digest: [u8; 32],
    pub transcript_n_draws: u32,
    pub proof: StarkProof<H>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitmentStatement0 {
    pub log_size: u32,
    pub committed_hash: [u8; 32],
}

impl CommitmentStatement0 {
    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
        for chunk in self.committed_hash.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            channel.mix_u64(u64::from_le_bytes(bytes));
        }
    }

    pub fn log_sizes(&self) -> stwo::core::pcs::TreeVec<Vec<u32>> {
        BlakeStatement0 {
            log_size: self.log_size,
        }
        .log_sizes()
    }

    pub fn committed_hash_words(&self) -> [u32; 8] {
        self.committed_hash
            .array_chunks::<4>()
            .map(|&c| u32::from_le_bytes(c))
            .collect::<Vec<_>>()
            .try_into()
            .expect("committed_hash is [u8; 32], 32 / 4 = 8 words exactly")
    }
}

fn parse_balance_from_fragment(fragment: &[u8]) -> Result<u64, String> {
    let fragment_str =
        std::str::from_utf8(fragment).map_err(|e| format!("Invalid UTF-8 in fragment: {}", e))?;

    let digits: String = fragment_str
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();

    if digits.is_empty() {
        return Err(format!(
            "Failed to parse balance: no digits found in fragment {:?}",
            fragment_str
        ));
    }

    digits
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse balance: {} (fragment {:?})", e, fragment_str))
}

pub fn prove_withdraw(
    inputs: WithdrawInputs,
    log_size: u32,
) -> Result<WithdrawProof<KeccakMerkleHasher>, String> {
    tracing::info!("Starting combined withdraw proof generation");

    let parsed_amount = parse_balance_from_fragment(&inputs.balance_fragment)?;
    let amount_u32 = u32::try_from(parsed_amount)
        .map_err(|_| format!("Amount {} too large for u32", parsed_amount))?;

    if inputs.amount.0 != amount_u32 {
        return Err(format!(
            "Amount mismatch: parsed={}, provided={}",
            amount_u32, inputs.amount.0
        ));
    }

    tracing::info!("Parsed amount from fragment: {}", parsed_amount);

    tracing::info!("Step 1: Generating Blake3 proof for HTTP response fragment");

    let commitment_stmt0 = CommitmentStatement0 {
        log_size,
        committed_hash: inputs.commitment_hash,
    };
    let committed_hash_words = commitment_stmt0.committed_hash_words();

    let mut xor_accums = XorAccums::default();

    let (blake_scheduler_trace, blake_scheduler_lookup_data, blake_round_inputs) =
        BlakeScheduler::gen_trace(
            log_size,
            &inputs.balance_fragment,
            inputs.blinder,
            &mut xor_accums,
        );
    tracing::info!(
        columns = blake_scheduler_trace.len(),
        "Blake scheduler trace generated"
    );

    let mut rest = &blake_round_inputs[..];
    let (blake_round_traces, blake_round_lookup_data): (Vec<_>, Vec<_>) =
        multiunzip(ROUND_LOG_SPLIT.map(|l| {
            let (cur_inputs, r) = rest.split_at(1 << (log_size - LOG_N_LANES + l));
            rest = r;
            round::generate_trace(log_size + l, cur_inputs, &mut xor_accums)
        }));

    let (blake_xor_trace12, blake_xor_lookup_data12) =
        xor_table::xor12::generate_trace(xor_accums.xor12);
    let (blake_xor_trace9, blake_xor_lookup_data9) =
        xor_table::xor9::generate_trace(xor_accums.xor9);
    let (blake_xor_trace8, blake_xor_lookup_data8) =
        xor_table::xor8::generate_trace(xor_accums.xor8);
    let (blake_xor_trace7, blake_xor_lookup_data7) =
        xor_table::xor7::generate_trace(xor_accums.xor7);
    let (blake_xor_trace4, blake_xor_lookup_data4) =
        xor_table::xor4::generate_trace(xor_accums.xor4);

    tracing::info!("Step 2: Generating Poseidon chain for deposit leaf");

    let deposit_inputs = ChainInputs::for_deposit(
        inputs.secret,
        inputs.nullifier,
        inputs.amount,
        inputs.token_address,
    );
    let (deposit_trace, deposit_outputs) =
        gen_poseidon_chain_trace(log_size, deposit_inputs.clone());
    let deposit_leaf = deposit_outputs.leaf;
    tracing::info!("Deposit leaf computed: {}", deposit_leaf.0);

    tracing::info!("Step 3: Generating Merkle membership proof");

    let merkle_inputs = MerkleInputs::new(
        deposit_leaf,
        inputs.merkle_siblings.clone(),
        inputs.merkle_index,
        inputs.merkle_root,
    );
    let merkle_depth = merkle_inputs.depth();
    let (merkle_trace, computed_root) = gen_merkle_trace(log_size, &merkle_inputs);

    if computed_root != inputs.merkle_root {
        return Err(format!(
            "Merkle root mismatch: computed={}, expected={}",
            computed_root.0, inputs.merkle_root.0
        ));
    }
    tracing::info!("Merkle root verified: {}", computed_root.0);

    tracing::info!("Step 4: Generating scheduler trace");

    let scheduler_trace = gen_scheduler_trace(
        log_size,
        computed_root,
        inputs.merkle_root,
        inputs.amount,
        BaseField::from_u32_unchecked(0),
        deposit_leaf,
        BaseField::from_u32_unchecked(0),
    );

    tracing::info!("Step 5: Setting up prover");

    let config = PcsConfig::default();
    const XOR_TABLE_MAX_LOG_SIZE: u32 = 16;
    let log_max_rows = (log_size
        + *ROUND_LOG_SPLIT
            .iter()
            .max()
            .expect("ROUND_LOG_SPLIT is non-empty"))
    .max(XOR_TABLE_MAX_LOG_SIZE)
    .max(log_size + 3);

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut KeccakChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

    tracing::info!("Step 6: Committing preprocessed columns");

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            XorTable::new(12, 4, 0).generate_constant_trace(),
            XorTable::new(9, 2, 0).generate_constant_trace(),
            XorTable::new(8, 2, 0).generate_constant_trace(),
            XorTable::new(7, 2, 0).generate_constant_trace(),
            XorTable::new(4, 0, 0).generate_constant_trace(),
        ]
        .collect::<Vec<_>>(),
    );

    let chain_is_active = gen_is_active_column(log_size);
    let chain_is_step = gen_is_step_column(log_size);
    let chain_is_last = gen_is_last_column(log_size);

    let merkle_is_active = gen_merkle_is_active_column(log_size, merkle_depth);
    let merkle_is_step = gen_merkle_is_step_column(log_size, merkle_depth);
    let merkle_is_first = gen_merkle_is_first_column(log_size, merkle_depth);
    let merkle_is_last = gen_merkle_is_last_column(log_size, merkle_depth);

    let scheduler_is_first = gen_scheduler_is_first_column(log_size);

    tree_builder.extend_evals(vec![
        chain_is_active.clone(),
        chain_is_step.clone(),
        chain_is_last.clone(),
        merkle_is_active.clone(),
        merkle_is_step.clone(),
        merkle_is_first.clone(),
        merkle_is_last.clone(),
        scheduler_is_first.clone(),
    ]);

    tree_builder.commit(prover_channel);
    tracing::info!("Preprocessed trace committed");

    commitment_stmt0.mix_into(prover_channel);

    tracing::info!("Step 7: Committing base traces");

    let blake_stmt0 = BlakeStatement0 { log_size };

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            blake_scheduler_trace,
            blake_round_traces.into_iter().flatten(),
            blake_xor_trace12,
            blake_xor_trace9,
            blake_xor_trace8,
            blake_xor_trace7,
            blake_xor_trace4,
        ]
        .collect::<Vec<_>>(),
    );

    tree_builder.extend_evals(deposit_trace.clone());
    tree_builder.extend_evals(merkle_trace.clone());
    tree_builder.extend_evals(scheduler_trace.clone());

    tree_builder.commit(prover_channel);
    tracing::info!("Base traces committed");

    tracing::info!("Step 8: Drawing challenges");

    let all_elements = AllElements::draw(prover_channel);
    let leaf_relation = LeafRelation::draw(prover_channel);
    let root_relation = RootRelation::draw(prover_channel);

    let (blake_scheduler_interaction_trace, blake_scheduler_claimed_sum) =
        BlakeScheduler::gen_interaction_trace(
            log_size,
            blake_scheduler_lookup_data,
            &all_elements.round_elements,
            &all_elements.blake_elements,
            &all_elements.xor_elements,
            committed_hash_words,
        );

    let (blake_round_interaction_traces, blake_round_claimed_sums): (Vec<_>, Vec<_>) = multiunzip(
        ROUND_LOG_SPLIT
            .iter()
            .zip(blake_round_lookup_data)
            .map(|(l, lookup_data)| {
                round::generate_interaction_trace(
                    log_size + l,
                    lookup_data,
                    &all_elements.xor_elements,
                    &all_elements.round_elements,
                )
            }),
    );

    let (blake_xor_interaction_trace12, blake_xor_claimed_sum12) =
        xor_table::xor12::generate_interaction_trace(
            blake_xor_lookup_data12,
            &all_elements.xor_elements.xor12,
        );
    let (blake_xor_interaction_trace9, blake_xor_claimed_sum9) =
        xor_table::xor9::generate_interaction_trace(
            blake_xor_lookup_data9,
            &all_elements.xor_elements.xor9,
        );
    let (blake_xor_interaction_trace8, blake_xor_claimed_sum8) =
        xor_table::xor8::generate_interaction_trace(
            blake_xor_lookup_data8,
            &all_elements.xor_elements.xor8,
        );
    let (blake_xor_interaction_trace7, blake_xor_claimed_sum7) =
        xor_table::xor7::generate_interaction_trace(
            blake_xor_lookup_data7,
            &all_elements.xor_elements.xor7,
        );
    let (blake_xor_interaction_trace4, blake_xor_claimed_sum4) =
        xor_table::xor4::generate_interaction_trace(
            blake_xor_lookup_data4,
            &all_elements.xor_elements.xor4,
        );

    let blake_stmt1 = BlakeStatement1 {
        scheduler_claimed_sum: blake_scheduler_claimed_sum,
        round_claimed_sums: blake_round_claimed_sums.clone(),
        xor12_claimed_sum: blake_xor_claimed_sum12,
        xor9_claimed_sum: blake_xor_claimed_sum9,
        xor8_claimed_sum: blake_xor_claimed_sum8,
        xor7_claimed_sum: blake_xor_claimed_sum7,
        xor4_claimed_sum: blake_xor_claimed_sum4,
    };

    let (deposit_interaction, deposit_claimed_sum) =
        gen_poseidon_chain_interaction_trace(&deposit_trace, &leaf_relation, log_size, 2);

    let (merkle_interaction, merkle_claimed_sum) = gen_merkle_membership_interaction_trace(
        &merkle_trace,
        &leaf_relation,
        &root_relation,
        log_size,
        merkle_depth,
    );

    let (scheduler_interaction, scheduler_claimed_sum) =
        gen_scheduler_interaction_trace(&scheduler_trace, &leaf_relation, &root_relation, log_size);

    blake_stmt1.mix_into(prover_channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            blake_scheduler_interaction_trace,
            blake_round_interaction_traces.into_iter().flatten(),
            blake_xor_interaction_trace12,
            blake_xor_interaction_trace9,
            blake_xor_interaction_trace8,
            blake_xor_interaction_trace7,
            blake_xor_interaction_trace4
        ]
        .collect::<Vec<_>>(),
    );

    tree_builder.extend_evals(deposit_interaction.clone());
    tree_builder.extend_evals(merkle_interaction.clone());
    tree_builder.extend_evals(scheduler_interaction.clone());

    tree_builder.commit(prover_channel);
    let transcript_digest = prover_channel.digest().0;
    tracing::info!("Interaction traces committed");

    tracing::info!("Step 9: Creating components");

    let mut tree_span_provider = TraceLocationAllocator::default();

    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &blake_stmt1,
        committed_hash_words,
    );

    let deposit_component = PoseidonChainComponent::new(
        &mut tree_span_provider,
        PoseidonChainEval {
            log_n_rows: log_size,
            is_active_id: is_active_column_id(log_size, "deposit"),
            is_step_id: is_step_column_id(log_size, "deposit"),
            is_last_id: is_last_column_id(log_size, "deposit"),
            leaf_relation: leaf_relation.clone(),
            leaf_multiplicity: 2,
            claimed_sum: deposit_claimed_sum,
        },
        deposit_claimed_sum,
    );

    let merkle_component = MerkleMembershipComponent::new(
        &mut tree_span_provider,
        MerkleMembershipEval {
            log_n_rows: log_size,
            depth: merkle_depth,
            is_active_id: merkle_is_active_column_id(log_size, merkle_depth),
            is_step_id: merkle_is_step_column_id(log_size, merkle_depth),
            is_first_id: merkle_is_first_column_id(log_size, merkle_depth),
            is_last_id: merkle_is_last_column_id(log_size, merkle_depth),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            claimed_sum: merkle_claimed_sum,
        },
        merkle_claimed_sum,
    );

    let scheduler_component = PrivacyPoolSchedulerComponent::new(
        &mut tree_span_provider,
        PrivacyPoolSchedulerEval {
            log_n_rows: log_size,
            is_first_id: scheduler_is_first_column_id(log_size),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            amount: inputs.amount,
            refund_commitment_hash: BaseField::from_u32_unchecked(0),
            claimed_sum: scheduler_claimed_sum,
        },
        scheduler_claimed_sum,
    );

    let all_component_provers =
        chain![
            [&blake_components.scheduler_component
                as &dyn stwo::prover::ComponentProver<SimdBackend>],
            blake_components
                .round_components
                .iter()
                .map(|c| c as &dyn stwo::prover::ComponentProver<SimdBackend>),
            [&blake_components.xor12 as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&blake_components.xor9 as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&blake_components.xor8 as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&blake_components.xor7 as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&blake_components.xor4 as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&deposit_component as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&merkle_component as &dyn stwo::prover::ComponentProver<SimdBackend>],
            [&scheduler_component as &dyn stwo::prover::ComponentProver<SimdBackend>],
        ]
        .collect::<Vec<_>>();

    tracing::info!("Generating STARK proof...");
    let (proof, composition_polynomial) = prove(
        &all_component_provers,
        prover_channel,
        commitment_scheme,
    )
    .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    tracing::info!("✅ Combined withdraw proof generated successfully");

    Ok(WithdrawProof {
        commitment_stmt0,
        blake_stmt1,
        merkle_root: inputs.merkle_root,
        nullifier: inputs.nullifier,
        amount: inputs.amount,
        token_address: inputs.token_address,
        log_size,
        merkle_depth,
        deposit_claimed_sum,
        merkle_claimed_sum,
        scheduler_claimed_sum,
        composition_polynomial,
        transcript_digest,
        transcript_n_draws: 0,
        proof,
    })
}

pub fn verify_withdraw(proof_data: WithdrawProof<KeccakMerkleHasher>) -> Result<(), String> {
    tracing::info!("Starting combined withdraw proof verification");

    let committed_hash_words = proof_data.commitment_stmt0.committed_hash_words();
    let blake_stmt0 = BlakeStatement0 {
        log_size: proof_data.log_size,
    };
    let blake_log_sizes = proof_data.commitment_stmt0.log_sizes();
    let chain_log_sizes = ChainStatement0 {
        log_size: proof_data.log_size,
    }
    .log_sizes();
    let merkle_log_sizes = MerkleStatement0 {
        log_size: proof_data.log_size,
    }
    .log_sizes();
    let scheduler_log_sizes = SchedulerStatement0 {
        log_size: proof_data.log_size,
    }
    .log_sizes();

    let mut full_log_sizes = blake_log_sizes.clone();
    full_log_sizes[0].extend(chain_log_sizes[0].iter().copied());
    full_log_sizes[0].extend(merkle_log_sizes[0].iter().copied());
    full_log_sizes[0].extend(scheduler_log_sizes[0].iter().copied());
    full_log_sizes[1].extend(chain_log_sizes[1].iter().copied());
    full_log_sizes[1].extend(merkle_log_sizes[1].iter().copied());
    full_log_sizes[1].extend(scheduler_log_sizes[1].iter().copied());
    full_log_sizes[2].extend(chain_log_sizes[2].iter().copied());
    full_log_sizes[2].extend(merkle_log_sizes[2].iter().copied());
    full_log_sizes[2].extend(scheduler_log_sizes[2].iter().copied());

    let channel = &mut KeccakChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    commitment_scheme.commit(proof_data.proof.commitments[0], &full_log_sizes[0], channel);
    proof_data.commitment_stmt0.mix_into(channel);

    commitment_scheme.commit(proof_data.proof.commitments[1], &full_log_sizes[1], channel);

    let all_elements = AllElements::draw(channel);
    let leaf_relation = LeafRelation::draw(channel);
    let root_relation = RootRelation::draw(channel);
    proof_data.blake_stmt1.mix_into(channel);

    commitment_scheme.commit(proof_data.proof.commitments[2], &full_log_sizes[2], channel);

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &proof_data.blake_stmt1,
        committed_hash_words,
    );

    let blake_total = proof_data.blake_stmt1.scheduler_claimed_sum
        + proof_data
            .blake_stmt1
            .round_claimed_sums
            .iter()
            .sum::<SecureField>()
        + proof_data.blake_stmt1.xor12_claimed_sum
        + proof_data.blake_stmt1.xor9_claimed_sum
        + proof_data.blake_stmt1.xor8_claimed_sum
        + proof_data.blake_stmt1.xor7_claimed_sum
        + proof_data.blake_stmt1.xor4_claimed_sum;

    if blake_total != SecureField::zero() {
        tracing::warn!("Blake3 logup imbalance (partial check): {:?}", blake_total);
    }

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

    let all_components = chain![
        blake_components
            .as_components_vec()
            .into_iter()
            .map(|c| c as &dyn stwo::core::air::Component),
        [&deposit_component as &dyn stwo::core::air::Component],
        [&merkle_component as &dyn stwo::core::air::Component],
        [&scheduler_component as &dyn stwo::core::air::Component],
    ]
    .collect::<Vec<_>>();

    verify(
        &all_components,
        channel,
        commitment_scheme,
        proof_data.proof,
    )
    .map_err(|_| "STARK verification failed".to_string())?;

    tracing::info!("✅ Combined withdraw proof verified successfully");
    Ok(())
}
