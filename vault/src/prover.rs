//! Stateless prover. Drives `zkp::recursion::finalize_and_prove` with a
//! per-kind circuit body from [`crate::leaf_circuits`]. The returned
//! `ProofPayload` carries the Stwo proof bytes, the AIR-kind tag, a
//! split Poseidon digest of the public inputs, and the public-input
//! JSON for the host-side rendering and verifier re-hash.

use circuits::context::TraceContext;
use stwo::core::fields::m31::M31;

use crate::{
    air::{AIR_KIND_TAG_MAX, AirKind},
    error::{Error, Result},
    hash::public_input_digest,
    leaf_circuits,
    types::{LeafWitness, PublicInputs},
};

/// Self-describing serialized proof. Mirrors [`zkp::ProofPayload`] in
/// shape; the three public outputs are repurposed:
///
/// - `air_kind_tag` = [`AirKind`] discriminant (metadata)
/// - `digest_hi`    = top 31 bits of `public_input_digest(public_inputs)`
/// - `digest_lo`    = bottom 31 bits of the same digest
///
/// The `bytes` field is the canonical wire form: a Stwo proof envelope
/// whose constraint set is kind-specific. Two proofs of different kinds
/// carry different in-circuit constraints, so their `output_values[3..5]`
/// (constants-hash slots) differ — the verifier uses that to detect
/// cross-kind replay.
#[derive(Clone, Debug)]
pub struct ProofPayload {
    pub bytes: Vec<u8>,
    pub air_kind_tag: u32,
    pub digest_hi: u32,
    pub digest_lo: u32,
    pub public_inputs_json: String,
}

impl ProofPayload {
    pub fn proof_size_bytes(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Default)]
pub struct Prover;

impl Prover {
    pub fn new() -> Self {
        Self
    }

    /// Produce a real Stwo proof for one leaf in an Action's fold tree.
    ///
    /// The circuit body dispatched by `kind` runs over the supplied
    /// private `witness`; the leaf emits the canonical
    /// `(leaf_index, leaf_index, 1)` output triple so the zkp merge
    /// AIR's contiguity + count constraints are satisfied when this
    /// proof is folded with siblings.
    pub fn prove_leaf(
        &self,
        leaf_index: u32,
        kind: AirKind,
        public_inputs: &PublicInputs,
        witness: &LeafWitness,
    ) -> Result<ProofPayload> {
        let tag = kind.tag();
        if tag >= AIR_KIND_TAG_MAX {
            return Err(Error::AirKindOutOfRange {
                tag,
                max: AIR_KIND_TAG_MAX,
            });
        }

        let pi_json = serde_json::to_string(public_inputs)?;
        let pi_value: serde_json::Value = serde_json::from_str(&pi_json)?;
        let (digest_hi, digest_lo) = public_input_digest(&pi_value);

        // Build the per-kind circuit in a fresh trace context, prove,
        // and serialise. The circuit may panic during `validate_circuit`
        // if the witness does not satisfy a constraint — we catch and
        // convert to a clean Err. This is the boundary that turns
        // soundness-critical failures (which the framework signals via
        // panic in debug mode) into recoverable application errors.
        let leaf_index_m31 = M31::from(leaf_index);
        let prove_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Vec<u8>> {
                let mut ctx = TraceContext::default();
                leaf_circuits::dispatch(&mut ctx, leaf_index, tag, witness)?;
                let record = zkp::recursion::finalize_and_prove(
                    &mut ctx,
                    leaf_index_m31,
                    leaf_index_m31,
                    M31::from(1u32),
                )?;
                zkp::serialize::serialize_record(&record).map_err(Error::from)
            }));
        let bytes = match prove_result {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(e),
            Err(panic) => {
                let message = if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic.downcast_ref::<&str>() {
                    (*s).to_owned()
                } else {
                    "circuit validation panicked with an unknown payload".to_owned()
                };
                return Err(Error::CircuitValidationFailed { message });
            }
        };

        Ok(ProofPayload {
            bytes,
            air_kind_tag: tag,
            digest_hi,
            digest_lo,
            public_inputs_json: pi_json,
        })
    }

    /// Fold two child proofs into one parent. Delegates to zkp's merge
    /// AIR verbatim — the merge AIR is kind-agnostic; it only enforces
    /// leaf-index contiguity (`right.lo == left.hi + 1`) and count
    /// summation, both of which our per-kind leaves honour by emitting
    /// the canonical output triple.
    pub fn prove_merge(&self, left: &[u8], right: &[u8]) -> Result<ProofPayload> {
        let zkp_prover = zkp::Prover::new();
        let zkp_payload = zkp_prover.prove_merge(left, right)?;
        Ok(ProofPayload {
            bytes: zkp_payload.bytes,
            air_kind_tag: AirKind::ActionRoot.tag(),
            digest_hi: 0,
            digest_lo: 0,
            public_inputs_json: format!(
                r#"{{"air":"action_root","leaf_count":{},"lo":{},"hi":{}}}"#,
                zkp_payload.count, zkp_payload.lo, zkp_payload.hi
            ),
        })
    }
}
