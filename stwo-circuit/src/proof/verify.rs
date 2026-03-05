use num_traits::Zero;
use stwo::core::{
    channel::KeccakChannel,
    fields::qm31::SecureField,
    pcs::CommitmentSchemeVerifier,
    vcs::keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher},
    verifier::verify,
};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::{
    blake3::{AllElements, BlakeComponentsForIntegration, BlakeStatement0},
    proof::{ProofData, VerifyError},
};

pub fn verify_proof(proof_data: ProofData<KeccakMerkleHasher>) -> Result<(), VerifyError> {
    let committed_hash_words = proof_data.commitment_stmt0.committed_hash_words();
    let blake_stmt0 = BlakeStatement0 {
        log_size: proof_data.commitment_stmt0.log_size,
    };
    let blake_log_sizes = proof_data.commitment_stmt0.log_sizes();

    let channel = &mut KeccakChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    commitment_scheme.commit(
        proof_data.proof.commitments[0],
        &blake_log_sizes[0],
        channel,
    );
    proof_data.commitment_stmt0.mix_into(channel);

    commitment_scheme.commit(
        proof_data.proof.commitments[1],
        &blake_log_sizes[1],
        channel,
    );

    let all_elements = AllElements::draw(channel);
    proof_data.blake_stmt1.mix_into(channel);

    commitment_scheme.commit(
        proof_data.proof.commitments[2],
        &blake_log_sizes[2],
        channel,
    );

    let mut tree_span_provider = TraceLocationAllocator::default();
    let blake_components = BlakeComponentsForIntegration::new(
        &mut tree_span_provider,
        &all_elements,
        &blake_stmt0,
        &proof_data.blake_stmt1,
        committed_hash_words,
    );

    let claimed_sum = proof_data.blake_stmt1.scheduler_claimed_sum
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

    if claimed_sum != SecureField::zero() {
        return Err(VerifyError::LogupImbalance(claimed_sum));
    }

    verify::<KeccakMerkleChannel>(
        &blake_components.as_components_vec(),
        channel,
        commitment_scheme,
        proof_data.proof,
    )
    .map_err(|_| VerifyError::StarkVerification)
}
