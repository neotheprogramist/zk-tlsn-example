//! Soundness tripwires: mutate one transcript field at a time and assert
//! the prover or verifier rejects (or panics, since some upstream paths
//! `unwrap()` rather than returning `Err`). The tests fail only if a
//! mutated proof is silently accepted — that's the audit-relevant signal.

use std::panic::{AssertUnwindSafe, catch_unwind};

use stwo::core::fields::{m31::M31, qm31::QM31};
use zkp::{
    recursion::{ProofRecord, prove_base, prove_step},
    verify::verify_record,
};

/// Returns true if `prove_step(prev)` either returned `Err(_)` or panicked.
fn step_rejects(prev: ProofRecord) -> bool {
    match catch_unwind(AssertUnwindSafe(|| prove_step(prev))) {
        Ok(Ok(_)) => false,
        Ok(Err(_)) | Err(_) => true,
    }
}

#[test]
fn step_rejects_mutated_prev_output_value() {
    let mut base = prove_base().expect("base");
    base.circuit_proof.claim.output_values[0] += QM31::from(M31::from(1u32));
    assert!(
        step_rejects(base),
        "step accepted prev with corrupted claim.output_values[0]",
    );
}

#[test]
fn step_rejects_mutated_n_blake_gates() {
    let mut base = prove_base().expect("base");
    base.preprocessed.params.n_blake_gates += 1;
    assert!(
        step_rejects(base),
        "step accepted prev with corrupted preprocessed.params.n_blake_gates",
    );
}

#[test]
fn step_rejects_mutated_output_addresses() {
    let mut base = prove_base().expect("base");
    base.preprocessed.params.output_addresses[0] += 1;
    assert!(
        step_rejects(base),
        "step accepted prev with corrupted preprocessed.params.output_addresses[0]",
    );
}

#[test]
fn verify_rejects_mutated_preprocessed_root() {
    let r0 = prove_base().expect("base");
    let mut r1 = prove_step(r0).expect("step 1");
    if let Ok(extended) = &mut r1.circuit_proof.stark_proof {
        extended.proof.0.commitments[0].0[0] ^= 0x01;
    } else {
        panic!("step 1 stark_proof must be Ok");
    }
    assert!(
        verify_record(&r1).is_err(),
        "verify accepted record with corrupted commitments[0]",
    );
}
