//! Host-side verifier.
//!
//! Mirrors the channel/commit sequence in
//! `circuit_prover::prover::prove_circuit_with_precompute` and then hands off
//! to `stwo::core::verifier::verify`. This is a real STARK verification —
//! independent of the in-circuit verifiers the merge AIR uses to chain
//! proofs — and binds `record.{lo, hi, count}` to
//! `claim.output_values[0..3]` so a caller can rely on the public outputs
//! without trusting the prover.
//!
//! `Verifier` is zero-sized (instances are free); `verify` takes the
//! serialized proof bytes and returns the publicly-bound `(lo, hi, count)`.

use circuit_prover::{circuit_air::circuit_components::CircuitComponents, prover::CircuitProof};
use circuit_verifier::{
    circuit_claim::CircuitInteractionElements, relations::CommonLookupElements,
    statement::INTERACTION_POW_BITS,
};
use circuits::poseidon2_hasher::Poseidon2M31MerkleChannel;
use stwo::core::{
    air::{Component, Components},
    channel::{Channel, MerkleChannel},
    fields::{m31::M31, qm31::QM31},
    pcs::CommitmentSchemeVerifier,
};

use crate::{
    error::{Error, Result},
    recursion::ProofRecord,
    serialize::deserialize_record,
};

/// Public outputs surfaced by [`Verifier::verify`]. The `verified` flag is
/// always true on a successful return — the function returns `Err` if any
/// check fails — but it's serialized so the JS caller can read a uniform
/// shape from postMessage.
#[derive(Clone, Copy, Debug)]
pub struct VerifyOutput {
    pub lo: u32,
    pub hi: u32,
    pub count: u32,
    pub verified: bool,
}

#[derive(Default)]
pub struct Verifier;

impl Verifier {
    pub fn new() -> Self {
        Self
    }

    /// Verifies a serialized proof. Returns the publicly-bound
    /// `(lo, hi, count)` triple on success; `Err` otherwise.
    pub fn verify(&self, bytes: &[u8]) -> Result<VerifyOutput> {
        let record = deserialize_record(bytes)?;
        verify_record(&record)?;
        Ok(VerifyOutput {
            lo: record.lo.0,
            hi: record.hi.0,
            count: record.count.0,
            verified: true,
        })
    }
}

/// Internal verification used by `prove_merge`'s verify-after-prove and by
/// the in-process tests that hold a `ProofRecord` directly. The wasm-facing
/// path goes through [`Verifier::verify`] which layers deserialization on top.
///
/// `record.circuit_proof.components` is intentionally **not** consulted —
/// the verifier reconstructs the canonical component set from
/// `claim`, `interaction_claim`, channel-drawn `interaction_elements`, and
/// `metadata.pp_trace_ids`. This makes a serialized record (which drops
/// components on the wire to keep the envelope compact) host-verifiable
/// directly. The reconstruction happens twice: once with placeholder
/// interaction elements solely to derive per-tree column log sizes (needed
/// before the channel has produced the real elements), and once with the
/// real elements drawn after the trace commit, used for the actual
/// constraint evaluation inside `stwo::core::verifier::verify`.
pub fn verify_record(record: &ProofRecord) -> Result<()> {
    let CircuitProof {
        pcs_config,
        claim,
        interaction_pow_nonce,
        interaction_claim,
        channel_salt,
        ..
    } = &record.circuit_proof;
    let stark_proof = record.extended_stark_proof();

    // Pre-channel: build a placeholder component set just to query
    // `tree_log_sizes`. The interaction elements are dummies; column
    // shapes don't depend on their values.
    let placeholder_elements = CircuitInteractionElements {
        common_lookup_elements: CommonLookupElements::dummy(),
    };
    let placeholder_components = CircuitComponents::new(
        claim,
        &placeholder_elements,
        interaction_claim,
        &record.metadata.pp_trace_ids,
    )
    .components();
    let placeholder_refs: Vec<&dyn Component> =
        placeholder_components.iter().map(|c| c.as_ref()).collect();
    let tree_log_sizes = Components {
        components: placeholder_refs,
        n_preprocessed_columns: record.metadata.n_preprocessed_columns(),
    }
    .column_log_sizes();

    let mut channel = <Poseidon2M31MerkleChannel as MerkleChannel>::C::default();
    channel.mix_felts(&[(*channel_salt).into()]);
    pcs_config.mix_into(&mut channel);

    let mut commitment_scheme =
        CommitmentSchemeVerifier::<Poseidon2M31MerkleChannel>::new(*pcs_config);

    commitment_scheme.commit(
        stark_proof.proof.commitments[0],
        &tree_log_sizes[0],
        &mut channel,
    );
    claim.mix_into(&mut channel);
    commitment_scheme.commit(
        stark_proof.proof.commitments[1],
        &tree_log_sizes[1],
        &mut channel,
    );

    if !channel.verify_pow_nonce(INTERACTION_POW_BITS, *interaction_pow_nonce) {
        return Err(Error::InteractionPow);
    }
    channel.mix_u64(*interaction_pow_nonce);
    let interaction_elements = CircuitInteractionElements::draw(&mut channel);

    interaction_claim.mix_into(&mut channel);
    commitment_scheme.commit(
        stark_proof.proof.commitments[2],
        &tree_log_sizes[2],
        &mut channel,
    );

    // Real component set with channel-drawn interaction elements. Used
    // for constraint evaluation inside the upstream verifier.
    let real_components = CircuitComponents::new(
        claim,
        &interaction_elements,
        interaction_claim,
        &record.metadata.pp_trace_ids,
    )
    .components();
    let real_refs: Vec<&dyn Component> = real_components.iter().map(|c| c.as_ref()).collect();

    stwo::core::verifier::verify(
        &real_refs,
        &mut channel,
        &mut commitment_scheme,
        stark_proof.proof.clone(),
    )?;
    bind_outputs(record)
}

/// Total `output_values.len()` for both the leaf AIR and the merge AIR.
///
/// Slots `[0..3]` are the user-facing outputs (`lo`, `hi`, `count`) emitted
/// by `recursion::prove_leaf` / `prove_merge`. Slot `[3]` is the circuit-
/// constants hash appended by `circuit_common::finalize::finalize_context`
/// (called transitively by `PreprocessedCircuit::preprocess_circuit`). The
/// hash slot is a function of the circuit's constants — not of the witness —
/// so it's self-binding in the STARK proof: an attacker can't alter it
/// without producing a different valid proof against constants they don't
/// control. The host therefore binds `[0..3]` directly and trusts FRI
/// consistency for the rest.
const EXPECTED_OUTPUT_VALUES: usize = 4;

fn bind_outputs(record: &ProofRecord) -> Result<()> {
    let outputs = &record.circuit_proof.claim.output_values;
    if outputs.len() != EXPECTED_OUTPUT_VALUES {
        return Err(Error::OutputCardinalityMismatch {
            actual: outputs.len(),
        });
    }
    bind_one("lo", record.lo, outputs[0])?;
    bind_one("hi", record.hi, outputs[1])?;
    bind_one("count", record.count, outputs[2])?;
    Ok(())
}

fn bind_one(slot: &'static str, host: M31, claim: QM31) -> Result<()> {
    let expected: QM31 = host.into();
    if claim != expected {
        return Err(Error::OutputMismatch {
            slot,
            record: host.0,
            claim: format!("{claim:?}"),
        });
    }
    Ok(())
}
