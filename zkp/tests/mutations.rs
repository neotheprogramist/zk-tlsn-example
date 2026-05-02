//! Soundness tripwires: mutate one transcript or claim field at a time and
//! assert the merge prover or host verifier rejects (or panics, since some
//! upstream paths `unwrap()` rather than returning `Err`). The tests fail
//! only if a mutated proof is silently accepted — that's the audit-relevant
//! signal.

use std::panic::{AssertUnwindSafe, catch_unwind};

use stwo::core::fields::{m31::M31, qm31::QM31};
use zkp::{
    recursion::{ProofRecord, prove_leaf, prove_merge},
    verify::verify_record,
};

/// Returns true if `prove_merge(left, right)` either returned `Err(_)` or
/// panicked.
fn merge_rejects(left: ProofRecord, right: ProofRecord) -> bool {
    match catch_unwind(AssertUnwindSafe(|| prove_merge(left, right))) {
        Ok(Ok(_)) => false,
        Ok(Err(_)) | Err(_) => true,
    }
}

fn fresh_pair() -> (ProofRecord, ProofRecord) {
    let l0 = prove_leaf(0).expect("leaf 0");
    let l1 = prove_leaf(1).expect("leaf 1");
    (l0, l1)
}

#[test]
fn merge_rejects_mutated_left_output_value() {
    let (mut l0, l1) = fresh_pair();
    l0.circuit_proof.claim.output_values[0] += QM31::from(M31::from(1u32));
    assert!(
        merge_rejects(l0, l1),
        "merge accepted left with corrupted claim.output_values[0]",
    );
}

#[test]
fn merge_rejects_mutated_n_blake_gates() {
    let (mut l0, l1) = fresh_pair();
    l0.preprocessed.params.n_blake_gates += 1;
    assert!(
        merge_rejects(l0, l1),
        "merge accepted left with corrupted preprocessed.params.n_blake_gates",
    );
}

#[test]
fn merge_rejects_mutated_output_addresses() {
    let (mut l0, l1) = fresh_pair();
    l0.preprocessed.params.output_addresses[0] += 1;
    assert!(
        merge_rejects(l0, l1),
        "merge accepted left with corrupted preprocessed.params.output_addresses[0]",
    );
}

#[test]
fn verify_rejects_mutated_preprocessed_root() {
    let (l0, l1) = fresh_pair();
    let mut m01 = prove_merge(l0, l1).expect("merge 0-1");
    if let Ok(extended) = &mut m01.circuit_proof.stark_proof {
        extended.proof.0.commitments[0].0[0] ^= 0x01;
    } else {
        panic!("merge stark_proof must be Ok");
    }
    assert!(
        verify_record(&m01).is_err(),
        "verify accepted record with corrupted commitments[0]",
    );
}

#[test]
fn merge_rejects_non_contiguous_pair() {
    // Leaves 0 and 2 (skipping 1) are not contiguous; merge rejects
    // host-side before any expensive proving (`ContiguityViolated`).
    let l0 = prove_leaf(0).expect("leaf 0");
    let l2 = prove_leaf(2).expect("leaf 2");
    assert!(
        merge_rejects(l0, l2),
        "merge accepted non-contiguous (0,0) + (2,2) pair",
    );
}

#[test]
fn verify_rejects_mutated_count_record() {
    // Build a real merge, then tamper the prover-side `count` field so
    // host verifier's bind_outputs catches the mismatch with the claim.
    let (l0, l1) = fresh_pair();
    let mut m01 = prove_merge(l0, l1).expect("merge 0-1");
    m01.count = M31::from(99u32); // host claims 99, claim still says 2
    assert!(
        verify_record(&m01).is_err(),
        "verify accepted record with mismatched count",
    );
}
