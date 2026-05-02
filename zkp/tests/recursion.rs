use stwo::core::fields::m31::M31;
use zkp::{
    recursion::{prove_leaf, prove_merge},
    verify::verify_record,
};

#[test]
fn tree_of_four_leaves() {
    // Four independent leaves at indices 0..=3.
    let l0 = prove_leaf(0).expect("leaf 0");
    let l1 = prove_leaf(1).expect("leaf 1");
    let l2 = prove_leaf(2).expect("leaf 2");
    let l3 = prove_leaf(3).expect("leaf 3");

    for (record, idx) in [(&l0, 0u32), (&l1, 1), (&l2, 2), (&l3, 3)] {
        assert_eq!(record.lo, M31::from(idx));
        assert_eq!(record.hi, M31::from(idx));
        assert_eq!(record.count, M31::from(1u32));
        verify_record(record).expect("verify leaf");
    }

    // Two height-1 subtrees: merge(l0, l1) and merge(l2, l3).
    let m01 = prove_merge(l0, l1).expect("merge 0-1");
    assert_eq!(m01.lo, M31::from(0u32));
    assert_eq!(m01.hi, M31::from(1u32));
    assert_eq!(m01.count, M31::from(2u32));
    verify_record(&m01).expect("verify m01");

    let m23 = prove_merge(l2, l3).expect("merge 2-3");
    assert_eq!(m23.lo, M31::from(2u32));
    assert_eq!(m23.hi, M31::from(3u32));
    assert_eq!(m23.count, M31::from(2u32));
    verify_record(&m23).expect("verify m23");

    // Root: merge of the two subtrees. This is the recursion gate — its
    // in-circuit verifier verifies merge proofs, not leaf proofs, so passing
    // here proves the merge AIR can verify itself.
    let root = prove_merge(m01, m23).expect("merge root");
    assert_eq!(root.lo, M31::from(0u32));
    assert_eq!(root.hi, M31::from(3u32));
    assert_eq!(root.count, M31::from(4u32));
    verify_record(&root).expect("verify root");

    assert_eq!(
        root.circuit_proof.claim.output_values[2],
        M31::from(4u32).into(),
        "claim output[2] (count) must equal 4 for a 4-leaf tree",
    );
}
