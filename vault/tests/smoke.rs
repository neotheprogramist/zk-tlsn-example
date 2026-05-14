//! Native smoke tests for the vault crate. Exercises every per-kind
//! circuit through real Stwo proving and verification, including the
//! UserKey + OfferCancel AIRs that depend on the unified Poseidon2-M31
//! hash. Negative cases prove the circuits actually reject invalid
//! witnesses (it's not just a metadata tag).

use stwo::core::fields::m31::M31;
use vault::{
    AirKind, LeafWitness, Prover, PublicInputs, Verifier,
    poseidon::{RATE, hash_host},
    preimage::{LOGIC_KIND_ERC20, OWNER_KIND_USERKEY, PREIMAGE_LIMB_COUNT},
    types::{ComplianceConsumedEntry, CompliancePreimageEntry, UserKeyAuthEntry},
};

fn limbs_to_array(limbs: [M31; RATE]) -> [u32; 8] {
    core::array::from_fn(|i| limbs[i].0)
}

/// Host-side userkey_salt = Poseidon(nk_limbs). Length 8 (no domain
/// prefix; length-distinguished from auth_tag inputs).
fn poseidon_userkey_salt_limbs(nk_limbs: &[u32; 8]) -> [u32; 8] {
    let input: Vec<M31> = nk_limbs.iter().map(|&v| M31::from(v)).collect();
    limbs_to_array(hash_host(&input))
}

/// Host-side auth_tag = Poseidon(nk_limbs ‖ ad_limbs ‖ cm_limbs). Length 24.
fn poseidon_auth_tag_limbs(
    nk_limbs: &[u32; 8],
    ad_limbs: &[u32; 8],
    cm_limbs: &[u32; 8],
) -> [u32; 8] {
    let mut input = Vec::with_capacity(8 * 3);
    for &v in nk_limbs.iter() {
        input.push(M31::from(v));
    }
    for &v in ad_limbs.iter() {
        input.push(M31::from(v));
    }
    for &v in cm_limbs.iter() {
        input.push(M31::from(v));
    }
    limbs_to_array(hash_host(&input))
}

// ─── OfferSolve (real x+1=2 circuit) ──────────────────────────────────────

#[test]
fn offer_solve_x_plus_1_eq_2_succeeds_for_x_eq_1() {
    let prover = Prover::new();
    let verifier = Verifier::new();
    let pi = PublicInputs::OfferSolve {
        instance_salt_hex: "11".repeat(32),
        challenge_id: "x_plus_1_eq_2".to_owned(),
        challenge_declaration: serde_json::json!({ "equation": "x + 1 == 2" }),
    };
    let payload = prover
        .prove_leaf(
            0,
            AirKind::OfferSolve,
            &pi,
            &LeafWitness::OfferSolveXPlus1 { x: 1 },
        )
        .expect("prove with x=1 must succeed");
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

#[test]
fn offer_solve_x_plus_1_eq_2_fails_for_x_eq_2() {
    let prover = Prover::new();
    let pi = PublicInputs::OfferSolve {
        instance_salt_hex: "22".repeat(32),
        challenge_id: "x_plus_1_eq_2".to_owned(),
        challenge_declaration: serde_json::json!({ "equation": "x + 1 == 2" }),
    };
    let result = prover.prove_leaf(
        0,
        AirKind::OfferSolve,
        &pi,
        &LeafWitness::OfferSolveXPlus1 { x: 2 },
    );
    assert!(result.is_err(), "prove with x=2 must fail");
}

// ─── Conservation (real Σ in == Σ out + fee circuit) ─────────────────────

#[test]
fn conservation_balanced_succeeds() {
    let prover = Prover::new();
    let verifier = Verifier::new();
    let pi = PublicInputs::ConservationFungible {
        kind_label: "vault.usdc".to_owned(),
        consumed_amounts: vec![100],
        created_amounts: vec![99],
        fee_amount: 1,
    };
    let payload = prover
        .prove_leaf(
            0,
            AirKind::ConservationFungible,
            &pi,
            &LeafWitness::Conservation {
                consumed: vec![100],
                created: vec![99],
                fee: 1,
            },
        )
        .expect("balanced conservation must succeed");
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

#[test]
fn conservation_unbalanced_fails() {
    let prover = Prover::new();
    let pi = PublicInputs::ConservationFungible {
        kind_label: "vault.eth".to_owned(),
        consumed_amounts: vec![100],
        created_amounts: vec![50],
        fee_amount: 0,
    };
    let result = prover.prove_leaf(
        0,
        AirKind::ConservationFungible,
        &pi,
        &LeafWitness::Conservation {
            consumed: vec![100],
            created: vec![50],
            fee: 0,
        },
    );
    assert!(result.is_err(), "unbalanced conservation must fail");
}

#[test]
fn conservation_multi_in_multi_out_succeeds() {
    // 50 + 70 == 100 + 20 + 0 (the canonical scenario-3 example).
    let prover = Prover::new();
    let verifier = Verifier::new();
    let pi = PublicInputs::ConservationFungible {
        kind_label: "vault.eth".to_owned(),
        consumed_amounts: vec![50, 70],
        created_amounts: vec![100, 20],
        fee_amount: 0,
    };
    let payload = prover
        .prove_leaf(
            0,
            AirKind::ConservationFungible,
            &pi,
            &LeafWitness::Conservation {
                consumed: vec![50, 70],
                created: vec![100, 20],
                fee: 0,
            },
        )
        .unwrap();
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

// ─── Compliance / fold (digest-bound) ────────────────────────────────────

#[test]
fn digest_bound_compliance_leaf_round_trips() {
    let prover = Prover::new();
    let verifier = Verifier::new();
    let pi = PublicInputs::Compliance {
        action_digest_hex: "00".repeat(32),
        consumed_commitments_hex: vec!["aa".repeat(32)],
        created_commitments_hex: vec!["bb".repeat(32), "cc".repeat(32)],
        nullifiers_hex: vec!["dd".repeat(32)],
    };
    let payload = prover
        .prove_leaf(0, AirKind::Compliance, &pi, &LeafWitness::DigestBound)
        .unwrap();
    assert_eq!(payload.air_kind_tag, AirKind::Compliance.tag());
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

#[test]
fn fold_two_contiguous_leaves() {
    let prover = Prover::new();
    let verifier = Verifier::new();
    let pi_compliance = PublicInputs::Compliance {
        action_digest_hex: "00".repeat(32),
        consumed_commitments_hex: vec![],
        created_commitments_hex: vec![],
        nullifiers_hex: vec![],
    };
    let pi_conservation = PublicInputs::ConservationFungible {
        kind_label: "vault.usdc".to_owned(),
        consumed_amounts: vec![100],
        created_amounts: vec![99],
        fee_amount: 1,
    };
    let left = prover
        .prove_leaf(
            0,
            AirKind::Compliance,
            &pi_compliance,
            &LeafWitness::DigestBound,
        )
        .unwrap();
    let right = prover
        .prove_leaf(
            1,
            AirKind::ConservationFungible,
            &pi_conservation,
            &LeafWitness::Conservation {
                consumed: vec![100],
                created: vec![99],
                fee: 1,
            },
        )
        .unwrap();
    let merged = prover.prove_merge(&left.bytes, &right.bytes).unwrap();
    let out = verifier.verify(&merged.bytes, None).unwrap();
    assert!(out.verified);
}

// ─── UserKey (real Poseidon(nk) + per-resource auth_tag circuit) ─────────

#[test]
fn userkey_auth_succeeds_for_correct_nk() {
    let nk: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
    let userkey_salt = poseidon_userkey_salt_limbs(&nk);
    let ad: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let cm: [u32; 8] = [9, 10, 11, 12, 13, 14, 15, 16];
    let auth_tag = poseidon_auth_tag_limbs(&nk, &ad, &cm);
    let zero: [u32; 8] = [0; 8];
    let padding_auth_tag = poseidon_auth_tag_limbs(&nk, &zero, &zero);

    let witness = LeafWitness::UserKeyAuth {
        nk_limbs: nk,
        expected_userkey_salt_limbs: userkey_salt,
        consumed_auth_tags: vec![UserKeyAuthEntry {
            action_digest_limbs: ad,
            cm_limbs: cm,
            auth_tag_limbs: auth_tag,
        }],
        padding_filler: UserKeyAuthEntry {
            action_digest_limbs: zero,
            cm_limbs: zero,
            auth_tag_limbs: padding_auth_tag,
        },
    };
    let pi = PublicInputs::UserKey {
        action_digest_hex: "00".repeat(32),
        consumed_resources_userkey_salt_hex: vec![],
        auth_tags_hex: vec![],
    };
    let prover = Prover::new();
    let verifier = Verifier::new();
    let payload = prover
        .prove_leaf(0, AirKind::UserKey, &pi, &witness)
        .expect("userkey auth must succeed with correct nk");
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

#[test]
fn userkey_auth_fails_for_wrong_nk() {
    let nk_real: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
    let nk_wrong: [u32; 8] = [99, 99, 99, 99, 99, 99, 99, 99];
    let userkey_salt = poseidon_userkey_salt_limbs(&nk_real);
    let ad: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let cm: [u32; 8] = [9, 10, 11, 12, 13, 14, 15, 16];
    let auth_tag = poseidon_auth_tag_limbs(&nk_real, &ad, &cm);
    let zero: [u32; 8] = [0; 8];
    let padding_auth_tag = poseidon_auth_tag_limbs(&nk_wrong, &zero, &zero);
    let witness = LeafWitness::UserKeyAuth {
        nk_limbs: nk_wrong,
        expected_userkey_salt_limbs: userkey_salt,
        consumed_auth_tags: vec![UserKeyAuthEntry {
            action_digest_limbs: ad,
            cm_limbs: cm,
            auth_tag_limbs: auth_tag,
        }],
        padding_filler: UserKeyAuthEntry {
            action_digest_limbs: zero,
            cm_limbs: zero,
            auth_tag_limbs: padding_auth_tag,
        },
    };
    let pi = PublicInputs::UserKey {
        action_digest_hex: "00".repeat(32),
        consumed_resources_userkey_salt_hex: vec![],
        auth_tags_hex: vec![],
    };
    let prover = Prover::new();
    let result = prover.prove_leaf(0, AirKind::UserKey, &pi, &witness);
    assert!(
        result.is_err(),
        "userkey auth must fail when nk does not hash to the expected salt"
    );
}

// ─── Compliance (real cm + nf in-circuit verification, audit 3) ─────────

/// Build a canonical 38-limb preimage with the supplied salt/rho/rseed,
/// using a small fixed label_id and value_ref_hash (any 8-limb pre-hash
/// would do — the test doesn't care what they came from).
fn build_preimage_limbs(salt_seed: u32, rho_seed: u32, rseed_seed: u32) -> Vec<u32> {
    let mut p = vec![0u32; PREIMAGE_LIMB_COUNT];
    p[0] = LOGIC_KIND_ERC20;
    // label_id_limbs (8) — arbitrary distinct values.
    for i in 0..8 {
        p[1 + i] = 1000 + i as u32;
    }
    // value_ref_hash_limbs (8) — arbitrary distinct.
    for i in 0..8 {
        p[9 + i] = 2000 + i as u32;
    }
    p[17] = OWNER_KIND_USERKEY;
    // owner_salt_limbs (8)
    for i in 0..8 {
        p[18 + i] = salt_seed + i as u32;
    }
    // rho_limbs (4)
    for i in 0..4 {
        p[26 + i] = rho_seed + i as u32;
    }
    // rseed_limbs (8)
    for i in 0..8 {
        p[30 + i] = rseed_seed + i as u32;
    }
    p
}

fn cm_for(preimage: &[u32]) -> [u32; 8] {
    let input: Vec<M31> = preimage.iter().map(|&v| M31::from(v)).collect();
    limbs_to_array(hash_host(&input))
}

fn nf_for(witness: &[u32; 8], rho: &[u32; 4], cm: &[u32; 8]) -> [u32; 8] {
    let mut input = Vec::with_capacity(20);
    for &v in witness.iter() {
        input.push(M31::from(v));
    }
    for &v in rho.iter() {
        input.push(M31::from(v));
    }
    for &v in cm.iter() {
        input.push(M31::from(v));
    }
    limbs_to_array(hash_host(&input))
}

fn build_padding_consumed() -> ComplianceConsumedEntry {
    let preimage = vec![0u32; PREIMAGE_LIMB_COUNT];
    let cm = cm_for(&preimage);
    let witness = [0u32; 8];
    let rho = [0u32; 4];
    let nf = nf_for(&witness, &rho, &cm);
    ComplianceConsumedEntry {
        preimage_limbs: preimage,
        expected_cm_limbs: cm,
        witness_limbs: witness,
        rho_limbs: rho,
        expected_nf_limbs: nf,
    }
}

fn build_padding_created() -> CompliancePreimageEntry {
    let preimage = vec![0u32; PREIMAGE_LIMB_COUNT];
    let cm = cm_for(&preimage);
    CompliancePreimageEntry {
        preimage_limbs: preimage,
        expected_cm_limbs: cm,
    }
}

fn compliance_pi() -> PublicInputs {
    PublicInputs::Compliance {
        action_digest_hex: "00".repeat(32),
        consumed_commitments_hex: vec![],
        created_commitments_hex: vec![],
        nullifiers_hex: vec![],
    }
}

#[test]
fn compliance_succeeds_for_correct_cm_nf() {
    // One consumed + one created, both with correct cm/nf.
    let preimage_c = build_preimage_limbs(100, 200, 300);
    let cm_c = cm_for(&preimage_c);
    let witness: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
    let rho_c: [u32; 4] = core::array::from_fn(|i| preimage_c[26 + i]);
    let nf_c = nf_for(&witness, &rho_c, &cm_c);

    let preimage_d = build_preimage_limbs(400, 500, 600);
    let cm_d = cm_for(&preimage_d);

    let witness = LeafWitness::Compliance {
        consumed: vec![ComplianceConsumedEntry {
            preimage_limbs: preimage_c,
            expected_cm_limbs: cm_c,
            witness_limbs: witness,
            rho_limbs: rho_c,
            expected_nf_limbs: nf_c,
        }],
        created: vec![CompliancePreimageEntry {
            preimage_limbs: preimage_d,
            expected_cm_limbs: cm_d,
        }],
        padding_consumed: build_padding_consumed(),
        padding_created: build_padding_created(),
    };

    let prover = Prover::new();
    let verifier = Verifier::new();
    let pi = compliance_pi();
    let payload = prover
        .prove_leaf(0, AirKind::Compliance, &pi, &witness)
        .expect("compliance with correct cm/nf must succeed");
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

#[test]
fn compliance_fails_for_wrong_cm() {
    let preimage_c = build_preimage_limbs(100, 200, 300);
    let mut wrong_cm = cm_for(&preimage_c);
    wrong_cm[0] = wrong_cm[0].wrapping_add(1); // tamper one limb
    let witness_w: [u32; 8] = [1; 8];
    let rho_c: [u32; 4] = core::array::from_fn(|i| preimage_c[26 + i]);
    let nf_c = nf_for(&witness_w, &rho_c, &wrong_cm);

    let witness = LeafWitness::Compliance {
        consumed: vec![ComplianceConsumedEntry {
            preimage_limbs: preimage_c,
            expected_cm_limbs: wrong_cm, // <-- tampered
            witness_limbs: witness_w,
            rho_limbs: rho_c,
            expected_nf_limbs: nf_c,
        }],
        created: vec![],
        padding_consumed: build_padding_consumed(),
        padding_created: build_padding_created(),
    };
    let prover = Prover::new();
    let result = prover.prove_leaf(0, AirKind::Compliance, &compliance_pi(), &witness);
    assert!(
        result.is_err(),
        "compliance must fail when cm doesn't match Poseidon(preimage)"
    );
}

#[test]
fn compliance_fails_for_wrong_nf() {
    let preimage_c = build_preimage_limbs(100, 200, 300);
    let cm_c = cm_for(&preimage_c);
    let witness_w: [u32; 8] = [1; 8];
    let rho_c: [u32; 4] = core::array::from_fn(|i| preimage_c[26 + i]);
    let mut wrong_nf = nf_for(&witness_w, &rho_c, &cm_c);
    wrong_nf[0] = wrong_nf[0].wrapping_add(1); // tamper nf

    let witness = LeafWitness::Compliance {
        consumed: vec![ComplianceConsumedEntry {
            preimage_limbs: preimage_c,
            expected_cm_limbs: cm_c,
            witness_limbs: witness_w,
            rho_limbs: rho_c,
            expected_nf_limbs: wrong_nf, // <-- tampered
        }],
        created: vec![],
        padding_consumed: build_padding_consumed(),
        padding_created: build_padding_created(),
    };
    let prover = Prover::new();
    let result = prover.prove_leaf(0, AirKind::Compliance, &compliance_pi(), &witness);
    assert!(
        result.is_err(),
        "compliance must fail when nf doesn't match Poseidon(witness‖rho‖cm)"
    );
}

#[test]
fn compliance_fails_for_wrong_preimage() {
    // Honest cm/nf from the real preimage, but submit a *different* preimage.
    let real_preimage = build_preimage_limbs(100, 200, 300);
    let cm_real = cm_for(&real_preimage);
    let witness_w: [u32; 8] = [1; 8];
    let rho_real: [u32; 4] = core::array::from_fn(|i| real_preimage[26 + i]);
    let nf_real = nf_for(&witness_w, &rho_real, &cm_real);

    let mut tampered_preimage = real_preimage.clone();
    tampered_preimage[0] = LOGIC_KIND_ERC20 + 1; // alter logic kind

    let witness = LeafWitness::Compliance {
        consumed: vec![ComplianceConsumedEntry {
            preimage_limbs: tampered_preimage, // <-- tampered preimage
            expected_cm_limbs: cm_real,        // claims a cm that the real preimage produced
            witness_limbs: witness_w,
            rho_limbs: rho_real,
            expected_nf_limbs: nf_real,
        }],
        created: vec![],
        padding_consumed: build_padding_consumed(),
        padding_created: build_padding_created(),
    };
    let prover = Prover::new();
    let result = prover.prove_leaf(0, AirKind::Compliance, &compliance_pi(), &witness);
    assert!(
        result.is_err(),
        "compliance must fail when preimage doesn't hash to claimed cm"
    );
}

// ─── OfferCancel (real creator-credential + cancel-auth circuit) ─────────

#[test]
fn offer_cancel_auth_succeeds_for_creator() {
    let nk: [u32; 8] = [101, 102, 103, 104, 105, 106, 107, 108];
    let creator_salt = poseidon_userkey_salt_limbs(&nk);
    let ad: [u32; 8] = [200, 201, 202, 203, 204, 205, 206, 207];
    let cm: [u32; 8] = [300, 301, 302, 303, 304, 305, 306, 307];
    let cancel_tag = poseidon_auth_tag_limbs(&nk, &ad, &cm);
    let witness = LeafWitness::OfferCancelAuth {
        nk_creator_limbs: nk,
        creator_userkey_salt_limbs: creator_salt,
        action_digest_limbs: ad,
        cm_offer_limbs: cm,
        cancel_auth_tag_limbs: cancel_tag,
    };
    let pi = PublicInputs::OfferCancel {
        instance_salt_hex: "aa".repeat(32),
        creator_userkey_salt_hex: "bb".repeat(32),
        cancel_auth_tag_hex: "cc".repeat(32),
    };
    let prover = Prover::new();
    let verifier = Verifier::new();
    let payload = prover
        .prove_leaf(0, AirKind::OfferCancel, &pi, &witness)
        .expect("offer cancel must succeed for creator");
    let pi_json = serde_json::to_string(&pi).unwrap();
    let out = verifier.verify(&payload.bytes, Some(&pi_json)).unwrap();
    assert!(out.verified);
}

#[test]
fn offer_cancel_auth_fails_for_non_creator() {
    let nk_creator: [u32; 8] = [101, 102, 103, 104, 105, 106, 107, 108];
    let nk_attacker: [u32; 8] = [201, 202, 203, 204, 205, 206, 207, 208];
    let creator_salt = poseidon_userkey_salt_limbs(&nk_creator);
    let ad: [u32; 8] = [200; 8];
    let cm: [u32; 8] = [300; 8];
    let cancel_tag = poseidon_auth_tag_limbs(&nk_creator, &ad, &cm);
    let witness = LeafWitness::OfferCancelAuth {
        nk_creator_limbs: nk_attacker, // attacker doesn't know creator's nk
        creator_userkey_salt_limbs: creator_salt,
        action_digest_limbs: ad,
        cm_offer_limbs: cm,
        cancel_auth_tag_limbs: cancel_tag,
    };
    let pi = PublicInputs::OfferCancel {
        instance_salt_hex: "aa".repeat(32),
        creator_userkey_salt_hex: "bb".repeat(32),
        cancel_auth_tag_hex: "cc".repeat(32),
    };
    let prover = Prover::new();
    let result = prover.prove_leaf(0, AirKind::OfferCancel, &pi, &witness);
    assert!(
        result.is_err(),
        "offer cancel must fail when nk doesn't hash to creator's salt"
    );
}
