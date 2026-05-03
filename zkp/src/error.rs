//! Single boundary error for the zkp crate.
//!
//! Mirrors `zktls::Error` in shape: one enum, one `Result` alias, `#[from]`
//! conversions where the source error already names the failure cleanly.

use stwo::{core::verifier::VerificationError, prover::ProvingError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("leaf index {index} ≥ M31::P; cannot fit in field")]
    LeafIndexOutOfRange { index: u32 },

    #[error(
        "contiguity violated: left.hi = {left_hi}, right.lo = {right_lo} (expected right.lo == left.hi + 1)"
    )]
    ContiguityViolated { left_hi: u32, right_lo: u32 },

    #[error("merge would overflow leaf-index space: left.hi = {left_hi} (== M31::P − 1)")]
    IndexOverflow { left_hi: u32 },

    #[error(
        "merge count would overflow M31: left.count = {left_count}, right.count = {right_count}"
    )]
    CountOverflow { left_count: u32, right_count: u32 },

    /// A child proof claims a `pcs_config` that doesn't match the canonical
    /// one this crate proves under. Without this check, an adversary could
    /// downgrade `n_queries` on a child and the in-circuit verifier would
    /// happily verify the child against its own (weakened) config.
    #[error(
        "child pcs_config mismatch on {side}: child claimed weaker config than canonical (canonical n_queries = {canonical_n_queries}, child n_queries = {child_n_queries})"
    )]
    ChildPcsConfigMismatch {
        side: &'static str,
        canonical_n_queries: usize,
        child_n_queries: usize,
    },

    /// `prove_merge` produced a proof, but its host-side verifier failed.
    /// Means we're returning a structurally-broken proof; refuse rather than
    /// let it propagate up the recursion. Should never fire in practice; if
    /// it does, that's a real bug in the merge AIR or the host verifier.
    #[error("verify-after-prove failed: {0}")]
    VerifyAfterProveFailed(Box<Error>),

    #[error("interaction-phase PoW nonce invalid")]
    InteractionPow,

    /// Leaf and merge AIRs both emit user-facing `(lo, hi, count)` at
    /// `output_values[0..3]`; `circuit_common::finalize::finalize_context`
    /// appends two more outputs (the constants hash) at `[3..5]`. Anything
    /// else means the proof was produced by a different circuit and we
    /// refuse to host-verify it.
    #[error(
        "expected exactly 5 output values (lo, hi, count, constants_hash[0..2]); claim has {actual}"
    )]
    OutputCardinalityMismatch { actual: usize },

    /// One of `record.{lo, hi, count}` doesn't match `claim.output_values[i]`.
    /// The proof itself is valid but the asserted outputs are a lie.
    #[error("output binding mismatch at slot {slot}: record = {record}, claim = {claim}")]
    OutputMismatch {
        slot: &'static str,
        record: u32,
        claim: String,
    },

    /// A field that must hold a canonical M31 element (`< P`) was outside
    /// the valid range. Surfaced at the deserialize boundary so any
    /// downstream code can trust the record's M31 fields are in canonical
    /// form (per GUIDELINES §6, valid by construction).
    #[error("non-canonical M31 value at slot {slot}: {value} ≥ M31::P")]
    NonCanonicalField { slot: &'static str, value: u32 },

    /// A length / shape invariant on the deserialized envelope was violated.
    /// E.g. `pp_trace_log_sizes.len() != pp_trace_ids.len()`, or
    /// `pcs_config` doesn't match the canonical one.
    #[error("deserialized record metadata is inconsistent: {reason}")]
    MetadataInconsistent { reason: &'static str },

    #[error(
        "claim_log_sizes has length {got}, expected {expected} (= circuit_verifier::circuit_components::N_COMPONENTS)"
    )]
    ClaimLogSizesShape { got: usize, expected: usize },

    #[error(
        "interaction_claim_sums has length {got}, expected {expected} (= circuit_verifier::circuit_components::N_COMPONENTS)"
    )]
    InteractionClaimSumsShape { got: usize, expected: usize },

    #[error("cannot serialise an Err stark_proof: {0}")]
    StarkProofIsErr(ProvingError),

    #[error("circuit prover failed: {0}")]
    StarkProofFailed(#[from] ProvingError),

    #[error(transparent)]
    Stark(#[from] VerificationError),

    #[error("bincode codec: {0}")]
    Bincode(#[source] bincode::Error),
}

impl Error {
    pub(crate) fn check_canonical_m31(slot: &'static str, value: u32) -> Result<()> {
        const P: u32 = stwo::core::fields::m31::P;
        if value >= P {
            return Err(Error::NonCanonicalField { slot, value });
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(err: Error) -> Self {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}
