use itertools::{Itertools, chain, multiunzip};
use stwo::{
    core::{
        channel::KeccakChannel,
        pcs::PcsConfig,
        poly::circle::CanonicCoset,
        vcs::keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher},
    },
    prover::{
        CommitmentSchemeProver,
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::circle::PolyOps,
        prove,
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::{
    blake3::{
        AllElements, BlakeComponentsForIntegration, BlakeStatement0, BlakeStatement1,
        ROUND_LOG_SPLIT, XorAccums, preprocessed_columns::XorTable, round, scheduler, xor_table,
    },
    proof::{CommitmentStatement0, ProofData},
};

pub fn prove_commitment(
    x: &[u8],
    blinder: [u8; 16],
    hash: [u8; 32],
    log_size: u32,
) -> ProofData<KeccakMerkleHasher> {
    assert!(
        log_size >= LOG_N_LANES,
        "log_size must be >= LOG_N_LANES (got log_size={}, LOG_N_LANES={})",
        log_size,
        LOG_N_LANES
    );

    let commitment_stmt0 = CommitmentStatement0 {
        log_size,
        committed_hash: hash,
    };
    let committed_hash_words = commitment_stmt0.committed_hash_words();

    let mut xor_accums = XorAccums::default();

    let (blake_scheduler_trace, blake_scheduler_lookup_data, blake_round_inputs) =
        scheduler::gen_trace(log_size, x, blinder, &mut xor_accums);
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

    let config = PcsConfig::default();

    const XOR_TABLE_MAX_LOG_SIZE: u32 = 16;
    let log_max_rows = (log_size
        + *ROUND_LOG_SPLIT
            .iter()
            .max()
            .expect("ROUND_LOG_SPLIT is a non-empty const array"))
    .max(XOR_TABLE_MAX_LOG_SIZE);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut KeccakChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            XorTable::new(12, 4, 0).generate_constant_trace(),
            XorTable::new(9, 2, 0).generate_constant_trace(),
            XorTable::new(8, 2, 0).generate_constant_trace(),
            XorTable::new(7, 2, 0).generate_constant_trace(),
            XorTable::new(4, 0, 0).generate_constant_trace(),
        ]
        .collect_vec(),
    );
    tree_builder.commit(prover_channel);
    tracing::info!("Preprocessed trace committed");

    commitment_stmt0.mix_into(prover_channel);

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
        .collect_vec(),
    );
    tree_builder.commit(prover_channel);
    tracing::info!("Base trace committed");

    let all_elements = AllElements::draw(prover_channel);
    tracing::info!("Challenges drawn");

    let (blake_scheduler_interaction_trace, blake_scheduler_claimed_sum) =
        scheduler::gen_interaction_trace(
            log_size,
            blake_scheduler_lookup_data,
            &all_elements.round_elements,
            &all_elements.blake_elements,
            &all_elements.xor_elements,
            committed_hash_words,
        );
    tracing::info!(sum = ?blake_scheduler_claimed_sum, "Blake scheduler claimed sum");

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
        .collect_vec(),
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
    blake_stmt1.mix_into(prover_channel);
    tree_builder.commit(prover_channel);
    tracing::info!("Interaction trace committed");

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &blake_stmt1,
        committed_hash_words,
    );
    tracing::info!("Components created");

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
        ]
        .collect_vec();

    let proof = prove::<SimdBackend, KeccakMerkleChannel>(
        &all_component_provers,
        prover_channel,
        commitment_scheme,
    )
    .expect("Failed to generate proof");

    ProofData {
        commitment_stmt0,
        blake_stmt1,
        proof,
    }
}
