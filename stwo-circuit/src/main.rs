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

use crate::blake3::{AllElements, BlakeComponentsForIntegration, BlakeStatement0, BlakeStatement1, ROUND_LOG_SPLIT, XorAccums, preprocessed_columns::XorTable, round, scheduler::{self, compute_commitment_hash}, xor_table};

#[derive(Debug)]
pub enum VerifyError {
    LogupImbalance(SecureField),
    StarkVerification,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::LogupImbalance(sum) => {
                write!(f, "logup claimed sums do not balance (got {sum:?}, expected zero)")
            }
            VerifyError::StarkVerification => write!(f, "STARK verification failed"),
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofData<H: MerkleHasherLifted> {
    pub commitment_stmt0: CommitmentStatement0,
    pub blake_stmt1: BlakeStatement1,
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
        BlakeStatement0 { log_size: self.log_size }.log_sizes()
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

pub fn prove_commitment(
    balance_committed_part: &[u8],
    blinder: [u8; 16],
    balance_committed_hash: [u8; 32],
    log_size: u32,
) -> ProofData<Blake2sMerkleHasher> {
    let commitment_stmt0 = CommitmentStatement0 {
        log_size,
        committed_hash: balance_committed_hash,
    };
    let committed_hash_words = commitment_stmt0.committed_hash_words();

    let mut xor_accums = XorAccums::default();

    let (blake_scheduler_trace, blake_scheduler_lookup_data, blake_round_inputs) =
        scheduler::gen_trace(log_size, balance_committed_part, blinder, &mut xor_accums);
    tracing::info!(columns = blake_scheduler_trace.len(), "Blake scheduler trace generated");

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
        (log_size + *ROUND_LOG_SPLIT.iter().max().expect("ROUND_LOG_SPLIT is a non-empty const array")).max(XOR_TABLE_MAX_LOG_SIZE);
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

    ProofData {
        commitment_stmt0,
        blake_stmt1,
        proof,
    }
}

pub fn verify_proof(
    proof: StarkProof<Blake2sMerkleHasher>,
    blake_stmt1: BlakeStatement1,
    commitment_stmt0: CommitmentStatement0,
) -> Result<(), VerifyError> {
    let committed_hash_words = commitment_stmt0.committed_hash_words();
    let blake_stmt0 = BlakeStatement0 { log_size: commitment_stmt0.log_size };
    let blake_log_sizes = commitment_stmt0.log_sizes();

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(proof.config);

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
        &blake_stmt1,
        committed_hash_words,
    );

    let claimed_sum = blake_stmt1.scheduler_claimed_sum
        + blake_stmt1.round_claimed_sums.iter().sum::<SecureField>()
        + blake_stmt1.xor12_claimed_sum
        + blake_stmt1.xor9_claimed_sum
        + blake_stmt1.xor8_claimed_sum
        + blake_stmt1.xor7_claimed_sum
        + blake_stmt1.xor4_claimed_sum;

    if claimed_sum != SecureField::zero() {
        return Err(VerifyError::LogupImbalance(claimed_sum));
    }

    verify(&blake_components.as_components_vec(), channel, commitment_scheme, proof)
        .map_err(|_| VerifyError::StarkVerification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::scheduler::compute_commitment_hash;
    use proptest::prelude::*;

    fn x_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..=12)
    }

    fn run_proof_cycle(x: Vec<u8>, blinder: [u8; 16], hash: [u8; 32]) -> Result<(), VerifyError> {
        let proof_data = prove_commitment(&x, blinder, hash, 4);
        verify_proof(proof_data.proof, proof_data.blake_stmt1, proof_data.commitment_stmt0)
    }

    // Fast property tests: verify compute_commitment_hash properties without ZK overhead.
    proptest! {
        #[test]
        fn prop_hash_determinism(
            x in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            let h1 = compute_commitment_hash(&x, &blinder);
            let h2 = compute_commitment_hash(&x, &blinder);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn prop_hash_binding_on_input(
            x1 in x_strategy(),
            x2 in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            prop_assume!(x1 != x2);
            let h1 = compute_commitment_hash(&x1, &blinder);
            let h2 = compute_commitment_hash(&x2, &blinder);
            prop_assert_ne!(h1, h2, "Blake3 collision: different x gave identical hash");
        }

        #[test]
        fn prop_hash_hiding_via_blinder(
            x in x_strategy(),
            b1 in any::<[u8; 16]>(),
            b2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(b1 != b2);
            let h1 = compute_commitment_hash(&x, &b1);
            let h2 = compute_commitment_hash(&x, &b2);
            prop_assert_ne!(h1, h2, "Different blinders gave identical hash (hiding broken)");
        }
    }

    // Slow integration tests: full prove + verify cycle (~10-30s per case).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]

        // Completeness: honest prover always convinces verifier.
        #[test]
        fn prop_honest_proof_verifies(
            x in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            let hash = compute_commitment_hash(&x, &blinder);
            prop_assert!(run_proof_cycle(x, blinder, hash).is_ok());
        }

        // Soundness: flipping any byte of committed_hash causes LogupImbalance.
        #[test]
        fn prop_tampered_hash_rejected(
            x in x_strategy(),
            blinder in any::<[u8; 16]>(),
            flip_idx in 0usize..32usize,
        ) {
            let correct = compute_commitment_hash(&x, &blinder);
            let mut tampered = correct;
            tampered[flip_idx] ^= 0xFF;
            prop_assume!(tampered != correct);
            let err = run_proof_cycle(x, blinder, tampered)
                .expect_err("tampered hash should fail verification");
            prop_assert!(
                matches!(err, VerifyError::LogupImbalance(_)),
                "expected LogupImbalance, got: {err}"
            );
        }

        // Soundness: prover who uses wrong x but claims hash(correct_x) is rejected.
        #[test]
        fn prop_wrong_x_rejected(
            x1 in x_strategy(),
            x2 in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            prop_assume!(x1 != x2);
            let hash_x1 = compute_commitment_hash(&x1, &blinder);
            let err = run_proof_cycle(x2, blinder, hash_x1)
                .expect_err("wrong x should fail verification");
            prop_assert!(
                matches!(err, VerifyError::LogupImbalance(_)),
                "expected LogupImbalance, got: {err}"
            );
        }

        // Soundness: prover who uses wrong blinder but claims hash(x, correct_blinder) is rejected.
        #[test]
        fn prop_wrong_blinder_rejected(
            x in x_strategy(),
            b1 in any::<[u8; 16]>(),
            b2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(b1 != b2);
            let hash = compute_commitment_hash(&x, &b1);
            let err = run_proof_cycle(x, b2, hash)
                .expect_err("wrong blinder should fail verification");
            prop_assert!(
                matches!(err, VerifyError::LogupImbalance(_)),
                "expected LogupImbalance, got: {err}"
            );
        }
    }
}

#[apply(main!)]
async fn main() {
    let x = b"123456789012";
    let blinder = [0u8; 16];
    let expected_hash = compute_commitment_hash(x, &blinder);
    tracing::info!(hash = ?expected_hash, "Computed commitment hash");
    let proof_data = prove_commitment(x, blinder, expected_hash, 4);
    tracing::info!("Proof generated");
    match verify_proof(proof_data.proof, proof_data.blake_stmt1, proof_data.commitment_stmt0) {
        Ok(()) => tracing::info!("Verification: OK"),
        Err(e) => tracing::error!("Verification failed: {e}"),
    }
}
