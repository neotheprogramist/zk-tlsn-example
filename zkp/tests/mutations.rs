//! Soundness tripwires: mutate one transcript or claim field at a time and
//! assert the merge prover or host verifier rejects (or panics, since some
//! upstream paths `unwrap()` rather than returning `Err`). The tests fail
//! only if a mutated proof is silently accepted — that's the audit-relevant
//! signal.

use std::panic::{AssertUnwindSafe, catch_unwind};

use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    fri::FriConfig,
    pcs::PcsConfig,
};
use zkp::{
    recursion::{ProofRecord, prove_leaf, prove_merge},
    serialize::{SerializedProofRecord, deserialize_record, serialize_record},
    verifier::verify_record,
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
fn merge_rejects_mutated_output_addresses() {
    let (mut l0, l1) = fresh_pair();
    l0.metadata.output_addresses[0] += 1;
    assert!(
        merge_rejects(l0, l1),
        "merge accepted left with corrupted metadata.output_addresses[0]",
    );
}

/// Tampering `pp_trace_log_sizes` on an in-process child must drive the merge
/// AIR's in-circuit verifier to reject — the metadata is what
/// `add_in_context_verifier` rebuilds the child's `CircuitStatement` from, so
/// a divergence between metadata and the trace it commits to has to fail
/// either FRI consistency or the in-circuit verifier's structural checks.
#[test]
fn merge_rejects_mutated_pp_trace_log_sizes() {
    let (mut l0, l1) = fresh_pair();
    l0.metadata.pp_trace_log_sizes[0] = l0.metadata.pp_trace_log_sizes[0].wrapping_add(1);
    assert!(
        merge_rejects(l0, l1),
        "merge accepted left with corrupted metadata.pp_trace_log_sizes[0]",
    );
}

#[test]
fn merge_rejects_mutated_pp_trace_ids() {
    let (mut l0, l1) = fresh_pair();
    l0.metadata.pp_trace_ids[0].id.push('!');
    assert!(
        merge_rejects(l0, l1),
        "merge accepted left with corrupted metadata.pp_trace_ids[0].id",
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

/// `prove_merge` refuses a child whose `pcs_config.fri_config.n_queries`
/// has been downgraded. Without this check, the in-circuit verifier would
/// happily verify the child against its own (weakened) config.
#[test]
fn merge_rejects_child_with_weakened_pcs_config() {
    let (mut l0, l1) = fresh_pair();
    let original = l0.circuit_proof.pcs_config;
    let weakened = PcsConfig {
        pow_bits: original.pow_bits,
        fri_config: FriConfig::new(
            original.fri_config.log_last_layer_degree_bound,
            original.fri_config.log_blowup_factor,
            // Downgrade n_queries from canonical 3 → 1.
            1,
            original.fri_config.fold_step,
        ),
        lifting_log_size: original.lifting_log_size,
    };
    l0.circuit_proof.pcs_config = weakened;
    assert!(
        merge_rejects(l0, l1),
        "merge accepted child with downgraded n_queries",
    );
}

/// A leaf serialised through the cross-worker envelope and back is
/// equivalent to the original — `prove_merge` accepts it as a child and
/// produces a verifiable parent.
#[test]
fn roundtrip_serialize_record_then_merge() {
    let (l0, l1) = fresh_pair();
    let l0_bytes = serialize_record(&l0).expect("serialize l0");
    drop(l0);
    let l0_imported = deserialize_record(&l0_bytes).expect("deserialize l0");

    let m01 = prove_merge(l0_imported, l1).expect("merge with imported left");
    assert_eq!(m01.lo, M31::from(0u32));
    assert_eq!(m01.hi, M31::from(1u32));
    assert_eq!(m01.count, M31::from(2u32));
    verify_record(&m01).expect("verify merged-from-imported");
}

/// Corrupting bytes in the envelope must either fail to deserialise or
/// fail at the merge step. The bytes are at-rest data crossing a worker
/// boundary, so any silent acceptance is a real soundness gap.
#[test]
fn merge_rejects_corrupted_serialized_bytes() {
    let (l0, l1) = fresh_pair();
    let mut l0_bytes = serialize_record(&l0).expect("serialize l0");

    // Flip the very last byte (likely lands somewhere inside stark_proof bits;
    // bincode encodes vec lengths first, so end-of-buffer is proof payload).
    let last = l0_bytes.len() - 1;
    l0_bytes[last] ^= 0xff;

    // Either deserialise fails (the cheap path) or the merge AIR's in-circuit
    // verifier rejects the corrupted child. Both count as success; the only
    // failure here is silent acceptance of a tampered proof.
    let result = catch_unwind(AssertUnwindSafe(|| match deserialize_record(&l0_bytes) {
        Err(_) => Ok::<bool, ()>(true),
        Ok(l0_imported) => Ok(prove_merge(l0_imported, l1).is_err()),
    }));
    let rejected = matches!(result, Ok(Ok(true)) | Err(_));
    assert!(
        rejected,
        "merge accepted a child whose serialized bytes were corrupted",
    );
}

/// Deserialization rejects a hand-crafted envelope whose `lo` is outside
/// canonical M31 range. Per GUIDELINES §6 (valid by construction), this
/// surfaces at the boundary, not deep inside `verify_record`.
#[test]
fn deserialize_rejects_non_canonical_lo() {
    use stwo::core::fields::m31::P;
    let l0 = prove_leaf(0).expect("leaf 0");
    let mut envelope = SerializedProofRecord::from_record(&l0).expect("envelope");
    envelope.lo = P; // exactly at the boundary of canonical range
    let bytes = bincode::serialize(&envelope).expect("re-encode");
    assert!(
        deserialize_record(&bytes).is_err(),
        "deserialize accepted lo == M31::P (non-canonical)",
    );
}
