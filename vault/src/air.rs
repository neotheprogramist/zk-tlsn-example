//! AIR-kind enumeration. The discriminant value is packed into the leaf
//! proof's first public-output slot (`lo`); the host trusts that slot's
//! value because the proof envelope binds it via the Stwo verifier.
//!
//! Tag space is reserved deliberately small so we can extend the
//! enumeration without breaking deployed proofs. Kinds in the reserved
//! `0x00_00_00..0x00_FF_FF` range are first-class vault logics; the upper
//! `0x01_00_00..` range is reserved for kind-registry-allocated tags in
//! the future, mirroring the spec's permissionless kind registration.

use serde::{Deserialize, Serialize};

/// The first public-output slot of any vault leaf proof encodes one of
/// these discriminants. New variants append at the bottom — never
/// renumber, never reuse a retired tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum AirKind {
    /// Compliance attestation: every resource in `C ∪ D` has the canonical
    /// commitment shape, every consumed resource has the canonical
    /// nullifier shape, and `action_digest` is consistent.
    Compliance = 0,

    /// Fungible-conservation Logic-AIR: `Σ consumed == Σ created (+ fee
    /// if kind == USDC)`. The `kind` is part of the public-input record.
    ConservationFungible = 1,

    /// Offer "create" branch: the Offer resource appears in `D` and its
    /// co-created locked-token resource is present.
    OfferCreate = 2,

    /// Offer "solve" branch: a registered challenge family verifies a
    /// private witness against `challenge_public_hash`.
    OfferSolve = 3,

    /// Offer "cancel" branch: the canceller proves knowledge of `nk`
    /// such that `H_userkey(nk) == creator_userkey_salt`. In the toy this
    /// is JS-checked rather than in-circuit; the leaf still emits a tag
    /// so the proving viz shows the cancel branch as an explicit node.
    OfferCancel = 4,

    /// UserKey owner check: every UserKey-owned consumed resource has a
    /// valid `auth_tag` against `action_digest`. JS-checked in the toy.
    UserKey = 5,

    /// Action-AIR root: the merge fold over all per-action leaves.
    ActionRoot = 6,

    /// OfferSolve branch for the `tlsn_transfer` challenge family: opens
    /// a Poseidon transcript commitment in-circuit, parses the canonical
    /// fixed-width attestation layout (`tx_id ‖ to_user_id ‖ amount` as
    /// zero-padded ASCII decimal), and binds the parsed `to_user_id` /
    /// `amount` to the offer declaration's `expected_to_user_id` /
    /// `expected_amount`. Tagged at 7 (originally `TlsnAttestation`,
    /// renamed once it absorbed the offer-policy constraints).
    OfferSolveTlsnTransfer = 7,
}

/// Tag space cap. The tag is packed into one M31 slot so the cap is well
/// below `M31::P`. Reserving 24 bits leaves room for thousands of kinds.
pub const AIR_KIND_TAG_MAX: u32 = 1 << 24;

impl AirKind {
    pub fn tag(self) -> u32 {
        self as u32
    }

    pub fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            0 => Some(Self::Compliance),
            1 => Some(Self::ConservationFungible),
            2 => Some(Self::OfferCreate),
            3 => Some(Self::OfferSolve),
            4 => Some(Self::OfferCancel),
            5 => Some(Self::UserKey),
            6 => Some(Self::ActionRoot),
            7 => Some(Self::OfferSolveTlsnTransfer),
            _ => None,
        }
    }

    /// Stable human-readable name for logging and viz. Matches the
    /// `rename_all = "camelCase"` wire-form used by [`crate::PublicInputs`].
    pub fn name(self) -> &'static str {
        match self {
            Self::Compliance => "compliance",
            Self::ConservationFungible => "conservationFungible",
            Self::OfferCreate => "offerCreate",
            Self::OfferSolve => "offerSolve",
            Self::OfferCancel => "offerCancel",
            Self::UserKey => "userKey",
            Self::ActionRoot => "actionRoot",
            Self::OfferSolveTlsnTransfer => "offerSolveTlsnTransfer",
        }
    }
}
