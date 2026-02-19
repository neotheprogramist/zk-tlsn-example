use stwo_circuit::{ProofData, compute_commitment_hash, prove_commitment};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use tlsnotary::{
    Direction, HashAlgId, PlaintextHash, PlaintextHashSecret, TranscriptCommitment,
    TranscriptSecret,
};

use crate::{
    error::{Result, ZkTlsnError},
    padding::PaddingConfig,
};

pub type Proof = ProofData<Blake2sMerkleHasher>;

const PROOF_LOG_SIZE: u32 = 4;

pub fn generate_proof(
    transcript_commitments: &[TranscriptCommitment],
    transcript_secrets: &[TranscriptSecret],
    received_data: &[u8],
    padding_config: PaddingConfig,
) -> Result<Proof> {
    let received_commitment = extract_received_commitment(transcript_commitments)?;
    let received_secret = extract_received_secret(transcript_secrets)?;
    let (x, blinder, hash) = prepare_proof_input(
        received_data,
        received_commitment,
        received_secret,
        padding_config,
    )?;
    Ok(prove_commitment(&x, blinder, hash, PROOF_LOG_SIZE))
}

fn extract_received_commitment(commitments: &[TranscriptCommitment]) -> Result<PlaintextHash> {
    commitments
        .iter()
        .find_map(|c| match c {
            TranscriptCommitment::Hash(h) if h.direction == Direction::Received => Some(h.clone()),
            _ => None,
        })
        .ok_or(ZkTlsnError::NoReceivedCommitments)
}

fn extract_received_secret(secrets: &[TranscriptSecret]) -> Result<PlaintextHashSecret> {
    secrets
        .iter()
        .find_map(|s| match s {
            TranscriptSecret::Hash(h) if h.direction == Direction::Received => Some(h.clone()),
            _ => None,
        })
        .ok_or(ZkTlsnError::NoReceivedSecrets)
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: PlaintextHash,
    secret: PlaintextHashSecret,
    padding_config: PaddingConfig,
) -> Result<(Vec<u8>, [u8; 16], [u8; 32])> {
    if commitment.direction != Direction::Received || commitment.hash.alg != HashAlgId::BLAKE3 {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }
    if secret.direction != Direction::Received || secret.alg != HashAlgId::BLAKE3 {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }

    let range = commitment.idx.min().unwrap()..commitment.idx.end().unwrap();
    if range.len() != padding_config.commitment_length {
        return Err(ZkTlsnError::InvalidCommitmentLength {
            expected: padding_config.commitment_length,
            actual: range.len(),
        });
    }

    let x = received_data
        .get(range)
        .ok_or_else(|| ZkTlsnError::InvalidInput("commitment range out of bounds".into()))?
        .to_vec();

    let blinder: [u8; 16] = secret
        .blinder
        .as_bytes()
        .try_into()
        .map_err(|_| ZkTlsnError::InvalidInput("blinder must be exactly 16 bytes".into()))?;

    let hash: [u8; 32] = commitment
        .hash
        .value
        .as_bytes()
        .try_into()
        .map_err(|_| ZkTlsnError::InvalidInput("committed hash must be exactly 32 bytes".into()))?;

    let computed = compute_commitment_hash(&x, &blinder);
    if computed != hash {
        return Err(ZkTlsnError::HashVerificationFailed);
    }

    Ok((x, blinder, hash))
}
