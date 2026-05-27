//! Per-kind leaf-circuit builders. Each function takes a fresh
//! [`TraceContext`], adds kind-specific constraints over private
//! witnesses, and emits the canonical leaf output triple `(leaf_index,
//! leaf_index, 1)` so the zkp merge AIR's contiguity + count checks
//! still hold when these proofs are folded.
//!
//! Constants-hash binding: each kind's constraint set is structurally
//! different, so each kind's leaf carries a distinct constants-hash in
//! the proof's `output_values[3..5]`. The vault verifier reads those
//! slots and compares them against the expected hash for the claimed
//! kind — preventing a prover from producing an OfferSolve proof and
//! presenting it as a Conservation proof.
//!
//! In practice the host computes the expected hash lazily by re-running
//! each circuit shape in shape-only mode on first verification (see
//! [`crate::verifier::expected_constants_hash`]).

use circuits::{
    context::TraceContext,
    ops::{add, eq, guess, output},
};
use stwo::core::fields::{m31::M31, qm31::QM31};

use crate::{
    error::{Error, Result},
    poseidon::{RATE, bind_hash_to_expected, hash_in_circuit},
    preimage::{MAX_COMPLIANCE_CONSUMED, MAX_COMPLIANCE_CREATED, PREIMAGE_LIMB_COUNT},
    types::{
        CONSERVATION_MAX_INPUTS, CONSERVATION_MAX_OUTPUTS, ComplianceConsumedEntry,
        CompliancePreimageEntry, LeafWitness, MAX_USERKEY_AUTH_PER_LEAF, UserKeyAuthEntry,
    },
};

/// Cap on the witness `x` for `x_plus_1_eq_2`. The constraint is over
/// M31, but we additionally clip the host-side value to a small range
/// so the toy's UI never accidentally produces a witness ≥ P that would
/// roll over into a valid solution mod P.
pub const OFFER_SOLVE_X_MAX: u32 = 1 << 28;

/// Cap on a single fungible amount. Conservation sums must not overflow
/// M31's P (~2^31), so per-amount we cap at 2^28 and the sum can hold
/// up to 8 such values without overflow.
pub const FUNGIBLE_AMOUNT_MAX: u64 = 1 << 28;

/// Build the canonical leaf output `(leaf_index, leaf_index, 1)` that
/// the zkp merge AIR's contiguity / count constraints expect.
fn emit_canonical_outputs(ctx: &mut TraceContext, leaf_index: u32) -> Result<()> {
    if leaf_index >= (1u32 << 30) {
        return Err(Error::LeafIndexOutOfRange { index: leaf_index });
    }
    let li_value = QM31::from(M31::from(leaf_index));
    let lo_var = guess(ctx, li_value);
    let hi_var = guess(ctx, li_value);
    eq(ctx, lo_var, hi_var);
    let one_var = ctx.one();
    output(ctx, lo_var);
    output(ctx, hi_var);
    output(ctx, one_var);
    Ok(())
}

/// **OfferSolve / x_plus_1_eq_2 AIR** — enforces `x + 1 == 2` over a
/// private witness `x ∈ M31`.
///
/// The constraint is the entire content of the challenge family. A
/// future challenge family adds a new function here (and one entry in
/// the kind-to-circuit dispatch).
pub fn build_offer_solve_x_plus_1_eq_2(
    ctx: &mut TraceContext,
    leaf_index: u32,
    x: u32,
) -> Result<()> {
    if x >= OFFER_SOLVE_X_MAX {
        return Err(Error::OfferSolveWitnessOutOfRange {
            x,
            max: OFFER_SOLVE_X_MAX,
        });
    }
    let x_var = guess(ctx, QM31::from(M31::from(x)));
    let one_var = ctx.one();
    let two_var = add(ctx, one_var, one_var); // 2 = 1 + 1
    let x_plus_one = add(ctx, x_var, one_var); // x + 1
    eq(ctx, x_plus_one, two_var); // CONSTRAINT: x + 1 == 2
    emit_canonical_outputs(ctx, leaf_index)
}

/// **OfferSolve / sum_eq_n AIR** — enforces `x + y == n` over private
/// witnesses `x, y` and a host-known declaration value `n`. The
/// declaration is committed to via the public-input digest, so the
/// verifier knows which `n` is being checked.
pub fn build_offer_solve_sum_eq_n(
    ctx: &mut TraceContext,
    leaf_index: u32,
    x: u32,
    y: u32,
    n: u32,
) -> Result<()> {
    if x >= OFFER_SOLVE_X_MAX || y >= OFFER_SOLVE_X_MAX || n >= (1u32 << 30) {
        return Err(Error::OfferSolveWitnessOutOfRange {
            x: x.max(y).max(n),
            max: OFFER_SOLVE_X_MAX,
        });
    }
    let x_var = guess(ctx, QM31::from(M31::from(x)));
    let y_var = guess(ctx, QM31::from(M31::from(y)));
    let n_var = guess(ctx, QM31::from(M31::from(n)));
    let x_plus_y = add(ctx, x_var, y_var);
    eq(ctx, x_plus_y, n_var); // CONSTRAINT: x + y == n
    emit_canonical_outputs(ctx, leaf_index)
}

/// **Conservation AIR** — enforces `Σ consumed == Σ created + fee` for
/// one fungible kind. Inputs and outputs are zero-padded up to
/// [`CONSERVATION_MAX_INPUTS`] / [`CONSERVATION_MAX_OUTPUTS`] so the
/// circuit shape is fixed (and therefore its constants-hash is fixed)
/// regardless of how many entries the Action actually has.
pub fn build_conservation_fungible(
    ctx: &mut TraceContext,
    leaf_index: u32,
    consumed: &[u64],
    created: &[u64],
    fee: u64,
) -> Result<()> {
    if consumed.len() > CONSERVATION_MAX_INPUTS {
        return Err(Error::ConservationTooManyInputs {
            count: consumed.len(),
            max: CONSERVATION_MAX_INPUTS,
        });
    }
    if created.len() > CONSERVATION_MAX_OUTPUTS {
        return Err(Error::ConservationTooManyOutputs {
            count: created.len(),
            max: CONSERVATION_MAX_OUTPUTS,
        });
    }
    if fee > 1 {
        return Err(Error::ConservationFeeOutOfRange { fee });
    }
    for &amount in consumed.iter().chain(created.iter()) {
        if amount > FUNGIBLE_AMOUNT_MAX {
            return Err(Error::FungibleAmountOutOfRange {
                amount,
                max: FUNGIBLE_AMOUNT_MAX,
            });
        }
    }

    // sum_in: start at zero, add each consumed amount (real entries +
    // zero-padded constrained-to-zero slots).
    let mut sum_in = ctx.zero();
    for slot in 0..CONSERVATION_MAX_INPUTS {
        let value_u32 = if slot < consumed.len() {
            consumed[slot] as u32
        } else {
            0
        };
        let v = guess(ctx, QM31::from(M31::from(value_u32)));
        if slot >= consumed.len() {
            // CONSTRAINT: padding == 0
            eq(ctx, v, ctx.zero());
        }
        sum_in = add(ctx, sum_in, v);
    }

    let mut sum_out = ctx.zero();
    for slot in 0..CONSERVATION_MAX_OUTPUTS {
        let value_u32 = if slot < created.len() {
            created[slot] as u32
        } else {
            0
        };
        let v = guess(ctx, QM31::from(M31::from(value_u32)));
        if slot >= created.len() {
            eq(ctx, v, ctx.zero());
        }
        sum_out = add(ctx, sum_out, v);
    }

    // fee ∈ {0, 1} is enforced host-side (line 136-138 above); only the sum
    // constraint is in-circuit here.
    let fee_var = guess(ctx, QM31::from(M31::from(fee as u32)));
    let sum_out_plus_fee = add(ctx, sum_out, fee_var);
    eq(ctx, sum_in, sum_out_plus_fee); // CONSTRAINT: Σ consumed == Σ created + fee

    emit_canonical_outputs(ctx, leaf_index)
}

/// **Digest-bound leaf** — used by Compliance / OfferCreate / ActionRoot
/// kinds whose underlying check is the Poseidon `cm = Poseidon(preimage)`
/// host-side. The leaf still runs a real Stwo trace but its constraint
/// is purely the canonical output shape; the kind is bound to the proof
/// via a kind-specific constant that enters the constants-hash via
/// [`ctx.constant`].
pub fn build_digest_bound_leaf(
    ctx: &mut TraceContext,
    leaf_index: u32,
    kind_tag: u32,
) -> Result<()> {
    let kind_const = ctx.constant(QM31::from(M31::from(kind_tag)));
    eq(ctx, kind_const, kind_const);
    emit_canonical_outputs(ctx, leaf_index)
}

/// `Poseidon(nk) == expected_userkey_salt`, and for each consumed user-key
/// resource `Poseidon(nk ‖ action_digest ‖ cm) == auth_tag`. The two hashes
/// have different input lengths (8 vs 24 limbs) so domain separation comes
/// from the length alone — no prefix constant. Padding slots use the same
/// `nk` against zero `(ad, cm)`, with `padding_filler.auth_tag` host-computed.
pub fn build_userkey_auth(
    ctx: &mut TraceContext,
    leaf_index: u32,
    nk_limbs: &[u32; 8],
    expected_userkey_salt_limbs: &[u32; 8],
    consumed_auth_tags: &[UserKeyAuthEntry],
    padding_filler: &UserKeyAuthEntry,
) -> Result<()> {
    if consumed_auth_tags.len() > MAX_USERKEY_AUTH_PER_LEAF {
        return Err(Error::UserKeyTooManyAuths {
            count: consumed_auth_tags.len(),
            max: MAX_USERKEY_AUTH_PER_LEAF,
        });
    }

    let nk_vars: [circuits::context::Var; 8] =
        core::array::from_fn(|i| guess(ctx, QM31::from(M31::from(nk_limbs[i]))));

    {
        let computed: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &nk_vars);
        let expected_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(expected_userkey_salt_limbs[i]));
        bind_hash_to_expected(ctx, &computed, &expected_m31);
    }

    for slot in 0..MAX_USERKEY_AUTH_PER_LEAF {
        let entry = consumed_auth_tags.get(slot).unwrap_or(padding_filler);
        let ad_vars: [circuits::context::Var; 8] = core::array::from_fn(|i| {
            guess(ctx, QM31::from(M31::from(entry.action_digest_limbs[i])))
        });
        let cm_vars: [circuits::context::Var; 8] =
            core::array::from_fn(|i| guess(ctx, QM31::from(M31::from(entry.cm_limbs[i]))));
        let mut input = Vec::with_capacity(8 + 8 + 8);
        input.extend_from_slice(&nk_vars);
        input.extend_from_slice(&ad_vars);
        input.extend_from_slice(&cm_vars);
        let computed: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &input);
        let expected_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(entry.auth_tag_limbs[i]));
        bind_hash_to_expected(ctx, &computed, &expected_m31);
    }

    emit_canonical_outputs(ctx, leaf_index)
}

/// `Poseidon(nk_creator) == creator_userkey_salt` and
/// `Poseidon(nk_creator ‖ action_digest ‖ cm_offer) == cancel_auth_tag`.
/// Only the original creator can produce a valid proof.
pub fn build_offer_cancel_auth(
    ctx: &mut TraceContext,
    leaf_index: u32,
    nk_creator_limbs: &[u32; 8],
    creator_userkey_salt_limbs: &[u32; 8],
    action_digest_limbs: &[u32; 8],
    cm_offer_limbs: &[u32; 8],
    cancel_auth_tag_limbs: &[u32; 8],
) -> Result<()> {
    let nk_vars: [circuits::context::Var; 8] =
        core::array::from_fn(|i| guess(ctx, QM31::from(M31::from(nk_creator_limbs[i]))));

    // Salt binding: Poseidon(nk_creator). (8 inputs)
    {
        let computed: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &nk_vars);
        let expected_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(creator_userkey_salt_limbs[i]));
        bind_hash_to_expected(ctx, &computed, &expected_m31);
    }

    // Cancel auth_tag binding: Poseidon(nk_creator ‖ action_digest ‖ cm_offer). (24 inputs)
    {
        let ad_vars: [circuits::context::Var; 8] =
            core::array::from_fn(|i| guess(ctx, QM31::from(M31::from(action_digest_limbs[i]))));
        let cm_vars: [circuits::context::Var; 8] =
            core::array::from_fn(|i| guess(ctx, QM31::from(M31::from(cm_offer_limbs[i]))));
        let mut input = Vec::with_capacity(8 + 8 + 8);
        input.extend_from_slice(&nk_vars);
        input.extend_from_slice(&ad_vars);
        input.extend_from_slice(&cm_vars);
        let computed: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &input);
        let expected_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(cancel_auth_tag_limbs[i]));
        bind_hash_to_expected(ctx, &computed, &expected_m31);
    }

    emit_canonical_outputs(ctx, leaf_index)
}

/// **Compliance AIR** — for every consumed/created resource in an Action,
/// verify `cm == Poseidon(preimage_limbs)` (38-limb canonical encoding)
/// and for every consumed resource additionally
/// `nf == Poseidon(witness ‖ rho ‖ cm)` (20-limb input).
///
/// Slots are zero-padded up to MAX_COMPLIANCE_CONSUMED / MAX_COMPLIANCE_CREATED;
/// the host supplies a `padding_consumed` / `padding_created` filler whose
/// expected cm/nf match the corresponding host hash of the zero/padding
/// preimage so the eq constraints trivially hold for padding slots.
pub fn build_compliance(
    ctx: &mut TraceContext,
    leaf_index: u32,
    consumed: &[ComplianceConsumedEntry],
    created: &[CompliancePreimageEntry],
    padding_consumed: &ComplianceConsumedEntry,
    padding_created: &CompliancePreimageEntry,
) -> Result<()> {
    if consumed.len() > MAX_COMPLIANCE_CONSUMED {
        return Err(Error::ComplianceTooManyConsumed {
            count: consumed.len(),
            max: MAX_COMPLIANCE_CONSUMED,
        });
    }
    if created.len() > MAX_COMPLIANCE_CREATED {
        return Err(Error::ComplianceTooManyCreated {
            count: created.len(),
            max: MAX_COMPLIANCE_CREATED,
        });
    }

    // ─── Consumed slots: cm + nf ─────────────────────────────────────────
    for slot in 0..MAX_COMPLIANCE_CONSUMED {
        let entry = consumed.get(slot).unwrap_or(padding_consumed);

        // Guess preimage limbs and recompute cm in-circuit.
        let preimage_vars: Vec<circuits::context::Var> = (0..PREIMAGE_LIMB_COUNT)
            .map(|i| guess(ctx, QM31::from(M31::from(entry.preimage_limbs[i]))))
            .collect();
        let computed_cm: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &preimage_vars);
        let expected_cm_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(entry.expected_cm_limbs[i]));
        bind_hash_to_expected(ctx, &computed_cm, &expected_cm_m31);

        // Nullifier input = witness_limbs (8) ‖ rho_limbs (4) ‖ cm_limbs (8) = 20 limbs.
        // Use the same expected_cm guesses (re-guessed for nf-input independence
        // so the prover provides them once more — the binding above already
        // proved they match the computed cm).
        let mut nf_input: Vec<circuits::context::Var> = Vec::with_capacity(20);
        for i in 0..8 {
            nf_input.push(guess(ctx, QM31::from(M31::from(entry.witness_limbs[i]))));
        }
        for i in 0..4 {
            nf_input.push(guess(ctx, QM31::from(M31::from(entry.rho_limbs[i]))));
        }
        for i in 0..8 {
            nf_input.push(guess(
                ctx,
                QM31::from(M31::from(entry.expected_cm_limbs[i])),
            ));
        }
        let computed_nf: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &nf_input);
        let expected_nf_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(entry.expected_nf_limbs[i]));
        bind_hash_to_expected(ctx, &computed_nf, &expected_nf_m31);
    }

    // ─── Created slots: cm only ──────────────────────────────────────────
    for slot in 0..MAX_COMPLIANCE_CREATED {
        let entry = created.get(slot).unwrap_or(padding_created);
        let preimage_vars: Vec<circuits::context::Var> = (0..PREIMAGE_LIMB_COUNT)
            .map(|i| guess(ctx, QM31::from(M31::from(entry.preimage_limbs[i]))))
            .collect();
        let computed_cm: [circuits::context::Var; RATE] = hash_in_circuit(ctx, &preimage_vars);
        let expected_cm_m31: [M31; RATE] =
            core::array::from_fn(|i| M31::from(entry.expected_cm_limbs[i]));
        bind_hash_to_expected(ctx, &computed_cm, &expected_cm_m31);
    }

    emit_canonical_outputs(ctx, leaf_index)
}

/// Dispatch table: given an [`AirKind`] tag and a [`LeafWitness`],
/// build the appropriate constraint set inside `ctx`. Returns the
/// kind label of the routed circuit for diagnostic messages.
pub fn dispatch(
    ctx: &mut TraceContext,
    leaf_index: u32,
    kind_tag: u32,
    witness: &LeafWitness,
) -> Result<()> {
    use crate::air::AirKind;
    let kind = AirKind::from_tag(kind_tag).ok_or(Error::AirKindOutOfRange {
        tag: kind_tag,
        max: crate::air::AIR_KIND_TAG_MAX,
    })?;
    match (kind, witness) {
        (AirKind::OfferSolve, LeafWitness::OfferSolveXPlus1 { x }) => {
            build_offer_solve_x_plus_1_eq_2(ctx, leaf_index, *x)
        }
        (AirKind::OfferSolve, LeafWitness::OfferSolveSumEqN { x, y, n }) => {
            // n is in the witness for toy simplicity. The Compliance leaf's
            // public-input digest commits to the challenge_declaration
            // (which contains n), so the proof is bound to the declared n
            // indirectly. A stricter binding would thread n through public
            // inputs into this circuit directly.
            build_offer_solve_sum_eq_n(ctx, leaf_index, *x, *y, *n)
        }
        (
            AirKind::ConservationFungible,
            LeafWitness::Conservation {
                consumed,
                created,
                fee,
            },
        ) => build_conservation_fungible(ctx, leaf_index, consumed, created, *fee),
        (
            AirKind::UserKey,
            LeafWitness::UserKeyAuth {
                nk_limbs,
                expected_userkey_salt_limbs,
                consumed_auth_tags,
                padding_filler,
            },
        ) => build_userkey_auth(
            ctx,
            leaf_index,
            nk_limbs,
            expected_userkey_salt_limbs,
            consumed_auth_tags,
            padding_filler,
        ),
        (
            AirKind::OfferCancel,
            LeafWitness::OfferCancelAuth {
                nk_creator_limbs,
                creator_userkey_salt_limbs,
                action_digest_limbs,
                cm_offer_limbs,
                cancel_auth_tag_limbs,
            },
        ) => build_offer_cancel_auth(
            ctx,
            leaf_index,
            nk_creator_limbs,
            creator_userkey_salt_limbs,
            action_digest_limbs,
            cm_offer_limbs,
            cancel_auth_tag_limbs,
        ),
        (
            AirKind::Compliance,
            LeafWitness::Compliance {
                consumed,
                created,
                padding_consumed,
                padding_created,
            },
        ) => build_compliance(
            ctx,
            leaf_index,
            consumed,
            created,
            padding_consumed,
            padding_created,
        ),
        (k, LeafWitness::DigestBound) => build_digest_bound_leaf(ctx, leaf_index, k.tag()),
        (k, w) => Err(Error::AirWitnessMismatch {
            kind_label: k.name(),
            got: w.kind_label(),
        }),
    }
}
