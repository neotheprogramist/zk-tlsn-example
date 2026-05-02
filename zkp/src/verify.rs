//! Host-side verifier for `ProofRecord`.
//!
//! Mirrors the channel/commit sequence in
//! `circuit_prover::prover::prove_circuit_with_precompute` and then hands off
//! to `stwo::core::verifier::verify`. This is a real STARK verification —
//! independent of the in-circuit verifiers the merge AIR uses to chain
//! proofs — and binds `record.{lo, hi, count}` to
//! `claim.output_values[0..3]` so a caller (JS, demo, host test) can rely on
//! the public outputs without trusting the prover.

use circuit_prover::prover::CircuitProof;
use circuit_verifier::{
    circuit_claim::CircuitInteractionElements, statement::INTERACTION_POW_BITS,
};
use stwo::{
    core::{
        air::{Component, Components},
        channel::{Channel, MerkleChannel},
        fields::{m31::M31, qm31::QM31},
        pcs::CommitmentSchemeVerifier,
        vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher},
        verifier::VerificationError,
    },
    prover::ProvingError,
};
use thiserror::Error;

use crate::recursion::ProofRecord;

#[derive(Debug, Error)]
pub enum VerifyError {
    /// `circuit_proof.stark_proof` is `Err`. Carries the upstream cause.
    #[error("circuit prover failed: {0}")]
    StarkProofFailed(ProvingError),
    /// Interaction-phase proof-of-work nonce did not satisfy the difficulty
    /// the in-circuit verifier was sealed with.
    #[error("interaction-phase PoW nonce invalid")]
    InteractionPow,
    /// `claim.output_values` had fewer than 3 entries — the leaf/merge AIR
    /// always emits exactly `(lo, hi, count)`. A different shape means the
    /// proof was produced by a different circuit and shouldn't be accepted.
    #[error("expected 3 output values (lo, hi, count); claim has {actual}")]
    OutputCardinalityMismatch { actual: usize },
    /// One of `record.{lo, hi, count}` does not match
    /// `claim.output_values[i]`. The proof itself is valid but the asserted
    /// outputs are a lie.
    #[error("output binding mismatch at slot {slot}: record = {record}, claim = {claim}")]
    OutputMismatch {
        slot: &'static str,
        record: u32,
        claim: String,
    },
    /// Underlying STARK verification failed.
    #[error(transparent)]
    Stark(#[from] VerificationError),
}

pub fn verify_record(record: &ProofRecord) -> Result<(), VerifyError> {
    verify_proof(&record.circuit_proof, &record.preprocessed)?;
    bind_outputs(record)?;
    Ok(())
}

fn verify_proof(
    circuit_proof: &CircuitProof<Blake2sM31MerkleHasher>,
    preprocessed: &circuit_common::preprocessed::PreprocessedCircuit,
) -> Result<(), VerifyError> {
    let CircuitProof {
        pcs_config,
        claim,
        interaction_pow_nonce,
        interaction_claim,
        components,
        stark_proof,
        channel_salt,
    } = circuit_proof;

    let stark_proof = stark_proof
        .as_ref()
        .map_err(|e| VerifyError::StarkProofFailed(*e))?;

    let component_refs: Vec<&dyn Component> = components.iter().map(|c| c.as_ref()).collect();
    let n_preprocessed_columns = preprocessed.preprocessed_trace.ids().len();
    let component_view = Components {
        components: component_refs.clone(),
        n_preprocessed_columns,
    };
    let tree_log_sizes = component_view.column_log_sizes();

    // Mirror the prover's channel + commit sequence exactly. The in-circuit
    // verifier replicates this same sequence; we run the host equivalent.
    let mut channel = <Blake2sM31MerkleChannel as MerkleChannel>::C::default();
    channel.mix_felts(&[(*channel_salt).into()]);
    pcs_config.mix_into(&mut channel);

    let mut commitment_scheme =
        CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(*pcs_config);

    // Tree 0: preprocessed.
    commitment_scheme.commit(
        stark_proof.proof.commitments[0],
        &tree_log_sizes[0],
        &mut channel,
    );

    // Tree 1: base trace (mix the public claim first, matching the prover).
    claim.mix_into(&mut channel);
    commitment_scheme.commit(
        stark_proof.proof.commitments[1],
        &tree_log_sizes[1],
        &mut channel,
    );

    // Interaction-phase PoW + element draw.
    if !channel.verify_pow_nonce(INTERACTION_POW_BITS, *interaction_pow_nonce) {
        return Err(VerifyError::InteractionPow);
    }
    channel.mix_u64(*interaction_pow_nonce);
    let _interaction_elements = CircuitInteractionElements::draw(&mut channel);

    // Tree 2: interaction trace (mix the interaction claim first).
    interaction_claim.mix_into(&mut channel);
    commitment_scheme.commit(
        stark_proof.proof.commitments[2],
        &tree_log_sizes[2],
        &mut channel,
    );

    stwo::core::verifier::verify(
        &component_refs,
        &mut channel,
        &mut commitment_scheme,
        stark_proof.proof.clone(),
    )?;
    Ok(())
}

fn bind_outputs(record: &ProofRecord) -> Result<(), VerifyError> {
    let outputs = &record.circuit_proof.claim.output_values;
    if outputs.len() < 3 {
        return Err(VerifyError::OutputCardinalityMismatch {
            actual: outputs.len(),
        });
    }
    bind_one("lo", record.lo, outputs[0])?;
    bind_one("hi", record.hi, outputs[1])?;
    bind_one("count", record.count, outputs[2])?;
    Ok(())
}

fn bind_one(slot: &'static str, host: M31, claim: QM31) -> Result<(), VerifyError> {
    let expected: QM31 = host.into();
    if claim != expected {
        return Err(VerifyError::OutputMismatch {
            slot,
            record: host.0,
            claim: format!("{claim:?}"),
        });
    }
    Ok(())
}
