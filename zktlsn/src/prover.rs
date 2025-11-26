use noir::{
    barretenberg::{prove::prove_ultra_honk, verify::get_ultra_honk_verification_key},
    blackbox_solver::blake3,
    witness::from_vec_str_to_witness_map,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tlsnotary::{
    Direction, HashAlgId, PlaintextHash, PlaintextHashSecret, TranscriptCommitment,
    TranscriptSecret,
};

use crate::{
    error::{Result, ZkTlsnError},
    padding::PaddingConfig,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub verification_key: Vec<u8>,
    pub proof: Vec<u8>,
}

impl Proof {
    pub fn new(verification_key: Vec<u8>, proof: Vec<u8>) -> Self {
        Self {
            verification_key,
            proof,
        }
    }
}

pub fn generate_proof(
    transcript_commitments: &[TranscriptCommitment],
    transcript_secrets: &[TranscriptSecret],
    received_data: &[u8],
    padding_config: PaddingConfig,
) -> Result<Proof> {
    let received_commitment = extract_received_commitment(transcript_commitments)?;
    let received_secret = extract_received_secret(transcript_secrets)?;
    let proof_input = prepare_proof_input(
        received_data,
        received_commitment,
        received_secret,
        padding_config,
    )?;

    generate_zk_proof(&proof_input)
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

#[derive(Debug, Clone)]
struct ProofInput {
    committed_hash: Vec<u8>,
    committed_data: Vec<u8>,
    blinder: Vec<u8>,
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: PlaintextHash,
    secret: PlaintextHashSecret,
    padding_config: PaddingConfig,
) -> Result<ProofInput> {
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

    let committed_data = received_data[range].to_vec();
    let blinder = secret.blinder.as_bytes().to_vec();
    let data_to_hash = [&committed_data[..], &blinder[..]].concat();
    let committed_hash = blake3(&data_to_hash).map_err(|_| ZkTlsnError::HashVerificationFailed)?;

    let tlsnotary_hash = commitment.hash.value.as_bytes();
    if tlsnotary_hash != committed_hash.as_slice() {
        return Err(ZkTlsnError::HashVerificationFailed);
    }

    Ok(ProofInput {
        committed_hash: committed_hash.to_vec(),
        committed_data,
        blinder,
    })
}

pub(crate) fn load_circuit_bytecode() -> Result<String> {
    const PROGRAM_JSON: &str = include_str!("../../target/circuit.json");
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    json["bytecode"]
        .as_str()
        .ok_or(ZkTlsnError::BytecodeNotFound)
        .map(String::from)
}

fn generate_zk_proof(input: &ProofInput) -> Result<Proof> {
    let bytecode = load_circuit_bytecode()?;
    let inputs: Vec<String> = [&input.committed_hash, &input.committed_data, &input.blinder]
        .iter()
        .flat_map(|v| v.iter().map(|b| b.to_string()))
        .collect();
    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();

    let witness = from_vec_str_to_witness_map(input_refs).map_err(ZkTlsnError::NoirError)?;
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(ZkTlsnError::NoirError)?;
    let proof =
        prove_ultra_honk(&bytecode, witness, vk.clone(), false).map_err(ZkTlsnError::NoirError)?;
    Ok(Proof::new(vk, proof))
}
