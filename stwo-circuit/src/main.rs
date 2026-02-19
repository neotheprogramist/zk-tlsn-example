#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

use macro_rules_attribute::apply;
use smol_macros::main;
use stwo_circuit::{compute_commitment_hash, prove_commitment, verify_proof};

#[cfg(test)]
mod tests {
    use stwo_circuit::{
        VerifyError, compute_commitment_hash, prove_commitment, verify_proof,
    };
    use proptest::prelude::*;

    fn x_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..=12)
    }

    fn run_proof_cycle(x: Vec<u8>, blinder: [u8; 16], hash: [u8; 32]) -> Result<(), VerifyError> {
        verify_proof(prove_commitment(&x, blinder, hash, 4))
    }

    proptest! {
        #[test]
        fn prop_hash_determinism(
            x in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            let h1 = compute_commitment_hash(&x, &blinder);
            let h2 = compute_commitment_hash(&x, &blinder);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn prop_hash_binding_on_input(
            x1 in x_strategy(),
            x2 in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            prop_assume!(x1 != x2);
            let h1 = compute_commitment_hash(&x1, &blinder);
            let h2 = compute_commitment_hash(&x2, &blinder);
            prop_assert_ne!(h1, h2, "Blake3 collision: different x gave identical hash");
        }

        #[test]
        fn prop_hash_hiding_via_blinder(
            x in x_strategy(),
            b1 in any::<[u8; 16]>(),
            b2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(b1 != b2);
            let h1 = compute_commitment_hash(&x, &b1);
            let h2 = compute_commitment_hash(&x, &b2);
            prop_assert_ne!(h1, h2, "Different blinders gave identical hash (hiding broken)");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]

        #[test]
        fn prop_honest_proof_verifies(
            x in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            let hash = compute_commitment_hash(&x, &blinder);
            prop_assert!(run_proof_cycle(x, blinder, hash).is_ok());
        }

        #[test]
        fn prop_tampered_hash_rejected(
            x in x_strategy(),
            blinder in any::<[u8; 16]>(),
            flip_idx in 0usize..32usize,
        ) {
            let correct = compute_commitment_hash(&x, &blinder);
            let mut tampered = correct;
            tampered[flip_idx] ^= 0xFF;
            prop_assume!(tampered != correct);
            let err = run_proof_cycle(x, blinder, tampered)
                .expect_err("tampered hash should fail verification");
            prop_assert!(
                matches!(err, VerifyError::LogupImbalance(_)),
                "expected LogupImbalance, got: {err}"
            );
        }

        #[test]
        fn prop_wrong_x_rejected(
            x1 in x_strategy(),
            x2 in x_strategy(),
            blinder in any::<[u8; 16]>(),
        ) {
            prop_assume!(x1 != x2);
            let hash_x1 = compute_commitment_hash(&x1, &blinder);
            let err = run_proof_cycle(x2, blinder, hash_x1)
                .expect_err("wrong x should fail verification");
            prop_assert!(
                matches!(err, VerifyError::LogupImbalance(_)),
                "expected LogupImbalance, got: {err}"
            );
        }

        #[test]
        fn prop_wrong_blinder_rejected(
            x in x_strategy(),
            b1 in any::<[u8; 16]>(),
            b2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(b1 != b2);
            let hash = compute_commitment_hash(&x, &b1);
            let err = run_proof_cycle(x, b2, hash)
                .expect_err("wrong blinder should fail verification");
            prop_assert!(
                matches!(err, VerifyError::LogupImbalance(_)),
                "expected LogupImbalance, got: {err}"
            );
        }
    }
}

#[apply(main!)]
async fn main() {
    let x = b"123456789012";
    let blinder = [0u8; 16];
    let hash = compute_commitment_hash(x, &blinder);
    tracing::info!(hash = ?hash, "Computed commitment hash");
    let proof_data = prove_commitment(x, blinder, hash, 4);
    tracing::info!("Proof generated");
    match verify_proof(proof_data) {
        Ok(()) => tracing::info!("Verification: OK"),
        Err(e) => tracing::error!("Verification failed: {e}"),
    }
}
