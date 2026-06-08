//! Single boundary error for the vault crate. Mirrors `zkp::Error` in shape.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// The caller asked for an AIR kind whose discriminant exceeds the
    /// reserved tag space. Tag space is `[0, 1 << 24)` so it always fits
    /// in M31; rejecting here keeps the leaf-index slot canonical.
    #[error("air_kind {tag} out of range [0, {max})")]
    AirKindOutOfRange { tag: u32, max: u32 },

    /// Caller invoked `verify(bytes, None)` on a non-`ActionRoot` proof.
    /// Every per-kind leaf binds to a public-input digest the verifier
    /// must recompute; supply the JSON.
    #[error("verify({kind:?}) requires expected_public_inputs (only ActionRoot may pass None)")]
    PublicInputsRequired { kind: crate::air::AirKind },

    /// The leaf-index value provided is outside the M31 range or the
    /// vault's per-action max. M31 is ~2^31; we conservatively reject
    /// values ≥ 2^30 so sums against `+1` cannot wrap.
    #[error("leaf_index {index} exceeds vault leaf-index cap")]
    LeafIndexOutOfRange { index: u32 },

    /// The OfferSolve witness value falls outside the M31-safe range.
    /// The toy clips far below P so accidental wraparound to a valid
    /// solution mod P is structurally impossible.
    #[error("offer_solve witness {x} ≥ max {max}")]
    OfferSolveWitnessOutOfRange { x: u32, max: u32 },

    /// Conservation AIR fed more inputs than the canonical shape supports.
    #[error("conservation has {count} consumed inputs (max {max})")]
    ConservationTooManyInputs { count: usize, max: usize },

    /// Conservation AIR fed more outputs than the canonical shape supports.
    #[error("conservation has {count} created outputs (max {max})")]
    ConservationTooManyOutputs { count: usize, max: usize },

    /// Conservation AIR fee value out of the {0, 1} range.
    #[error("conservation fee {fee} not in {{0, 1}}")]
    ConservationFeeOutOfRange { fee: u64 },

    /// A fungible amount exceeds the M31-safe sum cap.
    #[error("fungible amount {amount} ≥ max {max}")]
    FungibleAmountOutOfRange { amount: u64, max: u64 },

    /// The supplied `LeafWitness` variant does not match the requested
    /// AIR kind. Caught at the host before circuit construction.
    #[error("air {kind_label} expected a different witness variant; got {got}")]
    AirWitnessMismatch {
        kind_label: &'static str,
        got: &'static str,
    },

    /// Too many UserKey auth entries for one leaf. The circuit shape
    /// pads to MAX_USERKEY_AUTH_PER_LEAF; the host must split an
    /// Action with more user-key consumes across multiple leaves.
    #[error("userkey leaf has {count} auth entries (max {max})")]
    UserKeyTooManyAuths { count: usize, max: usize },

    /// Too many consumed resources for a single Compliance leaf.
    #[error("compliance leaf has {count} consumed resources (max {max})")]
    ComplianceTooManyConsumed { count: usize, max: usize },

    /// Too many created resources for a single Compliance leaf.
    #[error("compliance leaf has {count} created resources (max {max})")]
    ComplianceTooManyCreated { count: usize, max: usize },

    /// The proof's constants-hash (output slots 3..5) does not match the
    /// expected hash for the claimed AIR kind. Either the proof was
    /// produced for a different kind, or its constraint set was tampered
    /// with. Either way, refuse.
    #[error(
        "air-kind binding mismatch: claimed {claimed:?}, expected constants-hash {expected:?}, proof has {actual:?}"
    )]
    AirKindMismatch {
        claimed: crate::air::AirKind,
        expected: [String; 2],
        actual: [String; 2],
    },

    /// `proveAction` was called with fewer than two leaves. The fold
    /// expects at least one Compliance leaf and one Logic leaf.
    #[error("action has {leaves} leaves; need at least 2 to fold")]
    ActionTooSmall { leaves: usize },

    /// `serde_json` failed to encode/decode public inputs.
    #[error("json codec: {0}")]
    Json(#[from] serde_json::Error),

    /// The circuit-validation step detected that the supplied witness
    /// does not satisfy the kind's constraints. This is the soundness-
    /// critical failure path: a malicious prover cannot produce a valid
    /// proof for invalid witnesses. The framework asserts the violation
    /// inside `eq` / `validate_circuit`; we catch that panic here and
    /// surface it as a recoverable boundary error.
    #[error("circuit-validation rejected the witness: {message}")]
    CircuitValidationFailed { message: String },

    /// `bincode` failed to encode/decode the envelope.
    #[error("bincode codec: {0}")]
    Bincode(#[source] bincode::Error),

    /// TLSN attestation witness has a byte length other than the
    /// canonical [`crate::types::TLSN_ATT_LEN`] (32).
    #[error("tlsn attestation has {got} bytes, expected {expected}")]
    TlsnAttestationBadLength { got: usize, expected: usize },

    /// TLSN blinder witness has a byte length the circuit's input shape
    /// does not accept (the circuit's blinder column count is fixed).
    #[error("tlsn blinder has {got} bytes, expected {expected}")]
    TlsnBlinderBadLength { got: usize, expected: usize },

    /// Pass-through of an error raised by the underlying zkp crate's
    /// leaf/merge prover or verifier. The vault crate adds no new
    /// constraints on the envelope itself; everything zkp catches, we
    /// surface here unchanged.
    #[error(transparent)]
    Zkp(#[from] zkp::Error),
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(err: Error) -> Self {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}
