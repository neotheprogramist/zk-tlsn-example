use stwo_circuit::{compute_commitment_hash, prove_commitment, verify_proof, VerifyError};

fn sample_input() -> (Vec<u8>, [u8; 16]) {
    (b"123456789012".to_vec(), [7u8; 16])
}

#[test]
fn hash_is_deterministic() {
    let (x, blinder) = sample_input();
    let h1 = compute_commitment_hash(&x, &blinder);
    let h2 = compute_commitment_hash(&x, &blinder);
    assert_eq!(h1, h2);
}

// Only release mode
#[test]
fn honest_proof_verifies() {
    let (x, blinder) = sample_input();
    let hash = compute_commitment_hash(&x, &blinder);

    let proof = prove_commitment(&x, blinder, hash, 4);
    let result = verify_proof(proof);

    assert!(result.is_ok(), "expected proof to verify, got {result:?}");
}

// Only release mode
#[test]
fn wrong_hash_is_rejected() {
    let (x, blinder) = sample_input();
    let mut wrong_hash = compute_commitment_hash(&x, &blinder);
    wrong_hash[0] ^= 0xFF;

    let proof = prove_commitment(&x, blinder, wrong_hash, 4);
    let result = verify_proof(proof);

    assert!(
        matches!(result, Err(VerifyError::LogupImbalance(_))),
        "expected logup imbalance, got {result:?}"
    );
}
