use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};

use crate::{
    Proof,
    error::{Result, ZkTlsnError},
    prover::load_circuit_bytecode,
};

const HONK_FIELD_BYTES: usize = 32;
const COMMITTED_HASH_BYTES: usize = 32;

pub fn verify_proof(proof: &Proof) -> Result<()> {
    let bytecode = load_circuit_bytecode()?;
    let computed_vk =
        get_ultra_honk_verification_key(&bytecode, false).map_err(ZkTlsnError::NoirError)?;
    if computed_vk != proof.verification_key {
        return Err(ZkTlsnError::VerificationKeyMismatch);
    }
    let is_valid = verify_ultra_honk(proof.proof.clone(), proof.verification_key.clone())
        .map_err(ZkTlsnError::NoirError)?;
    if !is_valid {
        return Err(ZkTlsnError::InvalidProof);
    }
    Ok(())
}

pub fn extract_committed_hash_from_proof(proof: &Proof) -> Result<[u8; COMMITTED_HASH_BYTES]> {
    let proof_bytes = &proof.proof;
    if proof_bytes.is_empty() || !proof_bytes.len().is_multiple_of(HONK_FIELD_BYTES) {
        return Err(ZkTlsnError::InvalidInput(format!(
            "invalid proof length {}, expected multiple of {}",
            proof_bytes.len(),
            HONK_FIELD_BYTES
        )));
    }

    let expected_public_input_bytes = COMMITTED_HASH_BYTES * HONK_FIELD_BYTES;
    if proof_bytes.len() < expected_public_input_bytes {
        return Err(ZkTlsnError::InvalidInput(format!(
            "proof is too short: {} bytes, need at least {}",
            proof_bytes.len(),
            expected_public_input_bytes
        )));
    }

    let mut committed_hash = [0u8; COMMITTED_HASH_BYTES];
    for (index, field) in proof_bytes
        .chunks_exact(HONK_FIELD_BYTES)
        .take(COMMITTED_HASH_BYTES)
        .enumerate()
    {
        if field[..HONK_FIELD_BYTES - 1].iter().any(|&byte| byte != 0) {
            return Err(ZkTlsnError::InvalidInput(format!(
                "public input {index} does not fit in u8"
            )));
        }
        committed_hash[index] = field[HONK_FIELD_BYTES - 1];
    }

    Ok(committed_hash)
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
