//! Plain serde types for the public-input payload that travels alongside
//! every vault leaf proof, plus the private-witness types each kind's
//! Logic-AIR consumes.

use serde::{Deserialize, Serialize};

/// Private witness routed to one of the per-kind circuit builders in
/// [`crate::leaf_circuits`]. Each variant carries exactly the data the
/// kind's constraint set evaluates — no more, no less.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LeafWitness {
    OfferSolveXPlus1 {
        x: u32,
    },
    OfferSolveSumEqN {
        x: u32,
        y: u32,
        n: u32,
    },
    Conservation {
        consumed: Vec<u64>,
        created: Vec<u64>,
        fee: u64,
    },
    /// `Poseidon(nk) == expected_userkey_salt` plus per consumed user-key
    /// resource `Poseidon(nk ‖ action_digest ‖ cm) == auth_tag`. Padded
    /// to [`MAX_USERKEY_AUTH_PER_LEAF`]; `padding_filler` carries the
    /// pre-computed expected auth_tag for the zero `(ad, cm)` so unused
    /// slots' eq constraints trivially hold.
    UserKeyAuth {
        nk_limbs: [u32; 8],
        expected_userkey_salt_limbs: [u32; 8],
        consumed_auth_tags: Vec<UserKeyAuthEntry>,
        padding_filler: UserKeyAuthEntry,
    },
    /// `Poseidon(nk_creator) == creator_userkey_salt` and `Poseidon(
    /// nk_creator ‖ action_digest ‖ cm_offer) == cancel_auth_tag`. Only
    /// the original creator can produce a valid proof.
    OfferCancelAuth {
        nk_creator_limbs: [u32; 8],
        creator_userkey_salt_limbs: [u32; 8],
        action_digest_limbs: [u32; 8],
        cm_offer_limbs: [u32; 8],
        cancel_auth_tag_limbs: [u32; 8],
    },
    /// For every resource in the Action: `cm == Poseidon(preimage_limbs)`;
    /// additionally for every consumed: `nf == Poseidon(witness ‖ rho ‖ cm)`.
    /// Padded to MAX_COMPLIANCE_CONSUMED + MAX_COMPLIANCE_CREATED.
    Compliance {
        consumed: Vec<ComplianceConsumedEntry>,
        created: Vec<CompliancePreimageEntry>,
        padding_consumed: ComplianceConsumedEntry,
        padding_created: CompliancePreimageEntry,
    },
    /// No private witness; the proof's constraint set is the canonical
    /// leaf output emission only.
    DigestBound,
}

/// One created resource: preimage limbs (canonical 38-limb shape) and
/// the cm the prover claims for them. Vec rather than `[u32; 38]`
/// because serde doesn't auto-derive for arrays > 32 elements; the
/// canonical length is checked by the leaf-circuit dispatch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePreimageEntry {
    pub preimage_limbs: Vec<u32>,
    pub expected_cm_limbs: [u32; 8],
}

/// One consumed resource: same as created plus the nullifier witness
/// and expected nf. `rho_limbs` is supplied separately for nf-input
/// convenience; if it diverges from preimage slots 26..30 the cm
/// constraint fails first (so no independent check needed).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceConsumedEntry {
    pub preimage_limbs: Vec<u32>,
    pub expected_cm_limbs: [u32; 8],
    pub witness_limbs: [u32; 8],
    pub rho_limbs: [u32; 4],
    pub expected_nf_limbs: [u32; 8],
}

/// One consumed user-key-owned resource's authorisation data.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyAuthEntry {
    pub action_digest_limbs: [u32; 8],
    pub cm_limbs: [u32; 8],
    pub auth_tag_limbs: [u32; 8],
}

/// Maximum consumed user-key-owned resources per UserKey leaf. The
/// circuit shape pads to this; the host pre-computes a `padding_filler`
/// for unused slots. The e2e exercises up to 4 (Scenario 9: 3 ETH +
/// 1 USDC fee = 4 user-key consumes per Action).
pub const MAX_USERKEY_AUTH_PER_LEAF: usize = 4;

impl LeafWitness {
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::OfferSolveXPlus1 { .. } => "offerSolveXPlus1",
            Self::OfferSolveSumEqN { .. } => "offerSolveSumEqN",
            Self::Conservation { .. } => "conservation",
            Self::UserKeyAuth { .. } => "userKeyAuth",
            Self::OfferCancelAuth { .. } => "offerCancelAuth",
            Self::Compliance { .. } => "compliance",
            Self::DigestBound => "digestBound",
        }
    }
}

/// Maximum inputs and outputs the Conservation AIR's trace shape
/// accommodates. Each kind has ONE canonical circuit shape; we pad
/// shorter input lists with zero entries (constrained to zero
/// in-circuit) so the trace's column count is independent of the
/// Action's actual size.
pub const CONSERVATION_MAX_INPUTS: usize = 8;
pub const CONSERVATION_MAX_OUTPUTS: usize = 8;

/// Canonical resource preimage used by the host to compute a resource's
/// commitment off-circuit. Compliance asserts the preimage matches the
/// commitment the prover claims for that resource; the toy stores both
/// the preimage and the resulting commitment in the public-input record
/// so the verifier can reproduce the hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourcePreimage {
    /// VK digest (or symbolic name in the toy) of the kind logic.
    pub logic: String,
    /// CAIP-19 string for fungibles; `offer:<instance_salt_hex>` for
    /// Offer resources.
    pub label: String,
    /// `value_ref` rendered as a JSON value: amount for fungibles, a
    /// struct for Offers.
    pub value_ref: serde_json::Value,
    /// VK digest of the owning kind logic. `"userkey"` for user-owned,
    /// `"offer:<instance_salt_hex>"` for self-owned Offer resources.
    pub owner_kind: String,
    /// Instance salt of the owning logic.
    pub owner_salt_hex: String,
    /// 16-byte anti-contraction tag, hex-encoded.
    pub rho_hex: String,
    /// 32-byte hiding randomness, hex-encoded.
    pub rseed_hex: String,
}

/// Per-AIR-kind public-input record. One variant per [`crate::AirKind`].
/// Serialised via `serde_json` for the host-side digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "air", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PublicInputs {
    Compliance {
        action_digest_hex: String,
        consumed_commitments_hex: Vec<String>,
        created_commitments_hex: Vec<String>,
        nullifiers_hex: Vec<String>,
    },
    ConservationFungible {
        kind_label: String,
        consumed_amounts: Vec<u64>,
        created_amounts: Vec<u64>,
        fee_amount: u64,
    },
    OfferCreate {
        instance_salt_hex: String,
        locked_kind_label: String,
        locked_amount: u64,
        challenge_id: String,
        challenge_public_hash_hex: String,
    },
    OfferSolve {
        instance_salt_hex: String,
        challenge_id: String,
        /// The challenge's *public* declaration (e.g. the equation being
        /// solved); the witness `x` is private and lives on the prover
        /// side only. Carried as a JSON value to keep the registry
        /// extensible without changing this type.
        challenge_declaration: serde_json::Value,
    },
    OfferCancel {
        instance_salt_hex: String,
        creator_userkey_salt_hex: String,
        /// JS-computed `auth_tag` binding the cancel to `action_digest`.
        cancel_auth_tag_hex: String,
    },
    UserKey {
        action_digest_hex: String,
        consumed_resources_userkey_salt_hex: Vec<String>,
        auth_tags_hex: Vec<String>,
    },
    ActionRoot {
        action_digest_hex: String,
        leaf_count: u32,
        kinds_touched: Vec<String>,
    },
}
