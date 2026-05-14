//! Canonical fixed-size preimage encoding (38 M31 limbs per resource).
//!
//! This module defines the wire-format contract between the host (Rust +
//! JS via `vault.preimage.mjs`) and the in-circuit Compliance AIR's
//! `cm = Poseidon(preimage_limbs)` constraint. Both sides MUST agree on
//! the slot layout, the discriminant values, and the limb-packing rules.
//!
//! Layout (38 limbs total):
//!
//! ```text
//!   slot 0       = logic_kind_discriminant   (Erc20=1, Offer=2)
//!   slots 1..9   = label_id_limbs            (host pre-hash of the label string)
//!   slots 9..17  = value_ref_hash_limbs      (host pre-hash of the value_ref struct)
//!   slot 17      = owner_kind_discriminant   (UserKey=1, OfferSelf=2, Aggregator=3)
//!   slots 18..26 = owner_salt_limbs          (32 bytes packed 4-per-limb little-endian)
//!   slots 26..30 = rho_limbs                 (16 bytes packed 4-per-limb)
//!   slots 30..38 = rseed_limbs               (32 bytes packed 4-per-limb)
//! ```
//!
//! Discriminants are deliberately non-zero so a zero-filled limb array
//! cannot be misinterpreted as a real resource preimage — it just hashes
//! to a known "padding" digest the host pre-computes.

pub const PREIMAGE_LIMB_COUNT: usize = 38;

pub const LOGIC_KIND_ERC20: u32 = 1;
pub const LOGIC_KIND_OFFER: u32 = 2;

pub const OWNER_KIND_USERKEY: u32 = 1;
pub const OWNER_KIND_OFFER_SELF: u32 = 2;
pub const OWNER_KIND_AGGREGATOR: u32 = 3;

pub const SLOT_LOGIC_KIND: usize = 0;
pub const SLOT_LABEL_ID_START: usize = 1; // 8 limbs
pub const SLOT_LABEL_ID_END: usize = 9;
pub const SLOT_VALUE_REF_START: usize = 9; // 8 limbs
pub const SLOT_VALUE_REF_END: usize = 17;
pub const SLOT_OWNER_KIND: usize = 17;
pub const SLOT_OWNER_SALT_START: usize = 18; // 8 limbs
pub const SLOT_OWNER_SALT_END: usize = 26;
pub const SLOT_RHO_START: usize = 26; // 4 limbs
pub const SLOT_RHO_END: usize = 30;
pub const SLOT_RSEED_START: usize = 30; // 8 limbs
pub const SLOT_RSEED_END: usize = 38;

/// Maximum resources of each kind a single Compliance leaf can attest.
/// Larger Actions must split across multiple Compliance leaves.
pub const MAX_COMPLIANCE_CONSUMED: usize = 4;
pub const MAX_COMPLIANCE_CREATED: usize = 6;

/// Width of the nullifier-input limb array: witness(8) + rho(4) + cm(8) = 20.
pub const NULLIFIER_INPUT_LIMB_COUNT: usize = 20;
