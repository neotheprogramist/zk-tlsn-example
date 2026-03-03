use crate::{
    Proof,
    error::{Result, ZkTlsnError},
};

const COMMITTED_HASH_BYTES: usize = 32;

pub fn verify_proof(proof: &Proof) -> Result<()> {
    stwo_circuit::verify_proof(proof.clone()).map_err(|_| ZkTlsnError::InvalidProof)
}

pub fn extract_committed_hash_from_proof(proof: &Proof) -> Result<[u8; COMMITTED_HASH_BYTES]> {
    Ok(proof.commitment_stmt0.committed_hash)
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
