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
        return Err(ZkTlsnError::InvalidInput {
            context: "proof public inputs",
            details: format!(
                "expected at least {COMMITTED_HASH_BYTES}, got {}",
                proof.public_inputs.len()
            ),
        });
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
                return Err(ZkTlsnError::InvalidInput {
                    context: "commitment byte",
                    details: format!("public input {index} does not fit into a byte"),
                });
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
    let get_field = |index: usize, name: &'static str| -> Result<&[u8; HONK_FIELD_BYTES]> {
        proof
            .public_inputs
            .get(index)
            .ok_or(ZkTlsnError::InvalidInput {
                context: name,
                details: format!(
                    "proof public inputs too short: need index {index}, got length {}",
                    proof.public_inputs.len()
                ),
            })
    };

    Ok(ProofTransferFields {
        tx_id: field_word_to_u64(&field_word_hex(get_field(TX_ID_INDEX, "tx_id")?))?,
        to_user_id: field_word_to_u64(&field_word_hex(get_field(TO_USER_ID_INDEX, "to_user_id")?))?,
        amount: field_word_to_u64(&field_word_hex(get_field(AMOUNT_INDEX, "amount")?))?,
    })
}
