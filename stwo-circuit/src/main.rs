#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

mod trace;
mod eval;
mod blake3;

use itertools::{Itertools, chain, multiunzip};
use macro_rules_attribute::apply;
use num_traits::Zero;
use smol_macros::main;
use stwo::{core::{channel::{Blake2sChannel, Channel}, fields::qm31::SecureField, pcs::{CommitmentSchemeVerifier, PcsConfig}, poly::circle::CanonicCoset, proof::StarkProof, vcs_lifted::{MerkleHasherLifted, blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher}}, verifier::verify}, prover::{CommitmentSchemeProver, backend::simd::{SimdBackend, m31::LOG_N_LANES}, poly::circle::PolyOps, prove}};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::blake3::{AllElements, BlakeComponentsForIntegration, BlakeStatement0, BlakeStatement1, ROUND_LOG_SPLIT, XorAccums, preprocessed_columns::XorTable, round, scheduler::{self}, xor_table};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofData<H: MerkleHasherLifted> {
    commitment_stmt0: CommitmentStatement0,
    blake_stmt0: BlakeStatement0,
    blake_stmt1: BlakeStatement1,
    proof: StarkProof<H>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitmentStatement0 {
    pub log_size: u32,
    pub committed_hash: [u8; 32] 
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
        BlakeStatement0 { log_size: self.log_size }.log_sizes()
    }
}

fn prove_commitment(
    balance_committed_part: &[u8],
    blinder: [u8; 16],
    balance_committed_hash: [u8; 32],
    log_size: u32,
) -> ProofData<Blake2sMerkleHasher> {
    let (blake_scheduler_trace, blake_scheduler_lookup_data, blake_round_inputs) =
        scheduler::gen_trace(log_size, balance_committed_part, blinder);
    println!(
        "Blake scheduler trace generated: {} columns",
        blake_scheduler_trace.len()
    );

    let mut xor_accums = XorAccums::default();
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
    let log_max_rows =
        (log_size + *ROUND_LOG_SPLIT.iter().max().unwrap()).max(XOR_TABLE_MAX_LOG_SIZE);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    
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
    println!("Preprocessed trace committed");

    let commitment_stmt0 = CommitmentStatement0 {
        log_size,
        committed_hash: balance_committed_hash
    };

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
    println!("Base trace committed");

    let all_elements = AllElements::draw(prover_channel);
    println!("Challenges drawn");

    let (blake_scheduler_interaction_trace, blake_scheduler_claimed_sum) =
        scheduler::gen_interaction_trace(
            log_size,
            blake_scheduler_lookup_data,
            &all_elements.round_elements,
            &all_elements.blake_elements,
        );
    println!(
        "Blake scheduler claimed sum: {:?}",
        blake_scheduler_claimed_sum
    );

    let (blake_round_interaction_traces, blake_round_claimed_sums): (Vec<_>, Vec<_>) =
        multiunzip(ROUND_LOG_SPLIT.iter().zip(blake_round_lookup_data).map(
            |(l, lookup_data)| {
                round::generate_interaction_trace(
                    log_size + l,
                    lookup_data,
                    &all_elements.xor_elements,
                    &all_elements.round_elements,
                )
            },
        ));

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
        xor4_claimed_sum: blake_xor_claimed_sum4
    };
    blake_stmt1.mix_into(prover_channel);
    tree_builder.commit(prover_channel);
    println!("Interaction trace committed");

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &blake_stmt1,
    );
    println!("Components created");

    let all_component_provers = chain![
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

    let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
        &all_component_provers,
        prover_channel,
        commitment_scheme,
    )
    .expect("Failed to generate proof");

    println!("PROOF GENERATED!");
    ProofData {
        commitment_stmt0,
        blake_stmt0,
        blake_stmt1,
        proof
    }
}

fn verify_proof(
    proof: StarkProof<Blake2sMerkleHasher>,
    blake_stmt0: BlakeStatement0,
    blake_stmt1: BlakeStatement1,
    commitment_stmt0: CommitmentStatement0
) -> bool {
    let blake_log_sizes = blake_stmt0.log_sizes();

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(proof.config);

    commitment_scheme.commit(proof.commitments[0], &blake_log_sizes[0], channel);
    commitment_stmt0.mix_into(channel);

    commitment_scheme.commit(proof.commitments[1], &blake_log_sizes[1], channel);

    let all_elements = AllElements::draw(channel);
    blake_stmt1.mix_into(channel);

    commitment_scheme.commit(proof.commitments[2], &blake_log_sizes[2], channel);

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &blake_stmt1
    );
    println!("Components created");

    let claimed_sum = blake_stmt1.scheduler_claimed_sum
        + blake_stmt1.round_claimed_sums.iter().sum::<SecureField>()
        + blake_stmt1.xor12_claimed_sum
        + blake_stmt1.xor9_claimed_sum
        + blake_stmt1.xor8_claimed_sum
        + blake_stmt1.xor7_claimed_sum
        + blake_stmt1.xor4_claimed_sum;

    assert_eq!(claimed_sum, SecureField::zero());

    let verification_result = verify( &blake_components.as_components_vec(), channel, commitment_scheme, proof);
    match verification_result {
        Ok(()) => return true,
        Err(_) => return false
    }
}

#[apply(main!)]
async fn main() {
    let x = b"123";
    let blinder = [0u8; 16];
    let hash = [0u8; 32]; 
    let proof_data = prove_commitment(x, blinder, hash, 4);
    println!("Done: {:?}", proof_data.proof.commitments.len());
    let verify = verify_proof(proof_data.proof, proof_data.blake_stmt0, proof_data.blake_stmt1, proof_data.commitment_stmt0);
    print!("Verification result: {:?}", verify);
}
