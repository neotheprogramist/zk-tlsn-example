use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};
use tlsnotary::{Direction, PlaintextHash, TranscriptCommitment};

use crate::{
    Proof,
    error::{Result, ZkTlsnError},
    prover::load_circuit_bytecode,
};

pub fn verify_proof(transcript_commitments: &[TranscriptCommitment], proof: &Proof) -> Result<()> {
    let commitment = extract_received_commitment(transcript_commitments)?;

    verify_verification_key(&proof.verification_key)?;
    verify_committed_hash(&commitment, proof)?;
    verify_proof_validity(proof)?;

    tracing::info!("Proof verified successfully");
    Ok(())
}

fn extract_received_commitment(commitments: &[TranscriptCommitment]) -> Result<PlaintextHash> {
    commitments
        .iter()
        .find_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => {
                Some(hash.clone())
            }
            _ => None,
        })
        .ok_or(ZkTlsnError::NoReceivedCommitments)
}

fn verify_verification_key(provided_vk: &[u8]) -> Result<()> {
    let bytecode = load_circuit_bytecode()?;
    let computed_vk =
        get_ultra_honk_verification_key(&bytecode, false).map_err(ZkTlsnError::NoirError)?;

    if computed_vk != provided_vk {
        return Err(ZkTlsnError::VerificationKeyMismatch);
    }

    Ok(())
}

fn verify_committed_hash(commitment: &PlaintextHash, proof: &Proof) -> Result<()> {
    let hash_from_proof = extract_hash_from_proof(&proof.proof);
    let expected_hash = commitment.hash.value.as_bytes();

    if hash_from_proof != expected_hash {
        return Err(ZkTlsnError::CommittedHashMismatch);
    }

    tracing::debug!("Committed hash matches proof");
    Ok(())
}

fn extract_hash_from_proof(proof_bytes: &[u8]) -> Vec<u8> {
    proof_bytes
        .chunks(32)
        .take(32)
        .filter_map(|chunk| chunk.last().copied())
        .collect()
}

fn verify_proof_validity(proof: &Proof) -> Result<()> {
    let is_valid = verify_ultra_honk(proof.proof.clone(), proof.verification_key.clone())
        .map_err(ZkTlsnError::NoirError)?;

    if !is_valid {
        return Err(ZkTlsnError::InvalidProof);
    }

    tracing::debug!("Proof cryptographic validity confirmed");
    Ok(())
}
