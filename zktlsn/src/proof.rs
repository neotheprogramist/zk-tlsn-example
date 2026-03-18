use crate::{
    Proof,
    cli::{self, VerifierTarget},
    error::{Result, ZkTlsnError},
    recursive::{HONK_FIELD_BYTES, field_word_hex, field_word_to_u64},
};

const COMMITTED_HASH_BYTES: usize = 32;
const TX_ID_INDEX: usize = 32;
const TO_USER_ID_INDEX: usize = 33;
const AMOUNT_INDEX: usize = 34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofTransferFields {
    pub tx_id: u64,
    pub to_user_id: u64,
    pub amount: u64,
}

pub fn verify_proof(proof: &Proof) -> Result<()> {
    cli::verify_proof(
        &proof.proof,
        &proof.public_inputs,
        &proof.verification_key,
        VerifierTarget::NoirRecursive,
    )
}

pub fn extract_committed_hash_from_proof(proof: &Proof) -> Result<[u8; COMMITTED_HASH_BYTES]> {
    if proof.public_inputs.len() < COMMITTED_HASH_BYTES {
        return Err(ZkTlsnError::InvalidInput(format!(
            "proof public inputs are too short: expected at least {COMMITTED_HASH_BYTES}, got {}",
            proof.public_inputs.len()
        )));
    }

    // HONK_FIELD_BYTES is a const (32), so all slice indexing on [u8; HONK_FIELD_BYTES] is
    // compile-time checked and cannot panic.
    proof
        .public_inputs
        .iter()
        .take(COMMITTED_HASH_BYTES)
        .enumerate()
        .try_fold([0u8; COMMITTED_HASH_BYTES], |mut hash, (index, field)| {
            if field[..HONK_FIELD_BYTES - 1].iter().any(|&byte| byte != 0) {
                return Err(ZkTlsnError::InvalidInput(format!(
                    "public input {index} does not fit into a commitment byte"
                )));
            }
            hash[index] = field[HONK_FIELD_BYTES - 1];
            Ok(hash)
        })
}

pub fn verify_proof_against_hash(
    proof: &Proof,
    expected_committed_hash: &[u8; COMMITTED_HASH_BYTES],
) -> Result<()> {
    verify_proof(proof)?;
    let proof_committed_hash = extract_committed_hash_from_proof(proof)?;
    if &proof_committed_hash != expected_committed_hash {
        return Err(ZkTlsnError::CommittedHashMismatch);
    }
    Ok(())
}

pub fn extract_transfer_fields_from_proof(proof: &Proof) -> Result<ProofTransferFields> {
    let get_field = |index: usize, name: &str| -> Result<&[u8; HONK_FIELD_BYTES]> {
        proof.public_inputs.get(index).ok_or_else(|| {
            ZkTlsnError::InvalidInput(format!(
                "proof public inputs too short for {name}: need index {index}, got length {}",
                proof.public_inputs.len()
            ))
        })
    };

    Ok(ProofTransferFields {
        tx_id: field_word_to_u64(&field_word_hex(get_field(TX_ID_INDEX, "tx_id")?))?,
        to_user_id: field_word_to_u64(&field_word_hex(get_field(TO_USER_ID_INDEX, "to_user_id")?))?,
        amount: field_word_to_u64(&field_word_hex(get_field(AMOUNT_INDEX, "amount")?))?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AMOUNT_INDEX, COMMITTED_HASH_BYTES, ProofTransferFields, TO_USER_ID_INDEX, TX_ID_INDEX,
        extract_committed_hash_from_proof, extract_transfer_fields_from_proof,
    };
    use crate::test_fixtures::{load_attestation_fixture, load_attestation_proof_from_fixture};

    #[test]
    fn attestation_fixture_committed_hash_matches_fixture_json() {
        let fixture = load_attestation_fixture();
        let proof = load_attestation_proof_from_fixture();

        assert_eq!(
            extract_committed_hash_from_proof(&proof)
                .expect("extract committed hash")
                .to_vec(),
            fixture.attestation_committed_hash
        );
    }

    #[test]
    fn attestation_fixture_transfer_fields_match_fixture_json() {
        let fixture = load_attestation_fixture();
        let proof = load_attestation_proof_from_fixture();

        assert_eq!(
            extract_transfer_fields_from_proof(&proof).expect("extract transfer fields"),
            ProofTransferFields {
                tx_id: fixture.tx_id,
                to_user_id: fixture.to_user_id,
                amount: fixture.amount,
            }
        );
    }

    #[test]
    fn committed_hash_extraction_rejects_short_public_inputs() {
        let mut proof = load_attestation_proof_from_fixture();
        proof.public_inputs.truncate(COMMITTED_HASH_BYTES - 1);

        let error =
            extract_committed_hash_from_proof(&proof).expect_err("short public inputs should fail");
        assert!(
            error
                .to_string()
                .contains("proof public inputs are too short")
        );
    }

    #[test]
    fn committed_hash_extraction_rejects_non_byte_public_inputs() {
        let mut proof = load_attestation_proof_from_fixture();
        proof.public_inputs[0][0] = 1;

        let error = extract_committed_hash_from_proof(&proof)
            .expect_err("non-byte commitment word should fail");
        assert!(
            error
                .to_string()
                .contains("does not fit into a commitment byte")
        );
    }

    #[test]
    fn transfer_field_extraction_rejects_short_public_inputs() {
        let mut proof = load_attestation_proof_from_fixture();
        proof.public_inputs.truncate(AMOUNT_INDEX);

        let error = extract_transfer_fields_from_proof(&proof)
            .expect_err("short public inputs should fail");
        assert!(error.to_string().contains("proof public inputs too short"));
    }

    #[test]
    fn transfer_field_extraction_reads_expected_field_slots() {
        let proof = load_attestation_proof_from_fixture();

        assert_eq!(proof.public_inputs[TX_ID_INDEX][31], 1);
        assert_eq!(proof.public_inputs[TO_USER_ID_INDEX][31], 3);
        assert_eq!(proof.public_inputs[AMOUNT_INDEX][31], 25);
    }
}
