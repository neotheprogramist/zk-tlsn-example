use noir::{
    barretenberg::{
        prove::prove_ultra_honk, srs::setup_srs_from_bytecode,
        verify::get_ultra_honk_verification_key,
    },
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

    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof
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
        .find_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => {
                Some(hash.clone())
            }
            _ => None,
        })
        .ok_or(ZkTlsnError::NoReceivedCommitments)
}

fn extract_received_secret(secrets: &[TranscriptSecret]) -> Result<PlaintextHashSecret> {
    secrets
        .iter()
        .find_map(|secret| match secret {
            TranscriptSecret::Hash(hash) if hash.direction == Direction::Received => {
                Some(hash.clone())
            }
            _ => None,
        })
        .ok_or(ZkTlsnError::NoReceivedSecrets)
}

#[derive(Debug, Clone)]
struct ProofInput {
    balance_committed_hash: Vec<u8>,
    balance_committed_part: Vec<u8>,
    balance_blinder: Vec<u8>,
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: PlaintextHash,
    secret: PlaintextHashSecret,
    padding_config: PaddingConfig,
) -> Result<ProofInput> {
    validate_commitment(&commitment)?;
    validate_secret(&secret)?;

    let committed_range = commitment.idx.min().unwrap()..commitment.idx.end().unwrap();

    let committed_len = committed_range.end - committed_range.start;
    if committed_len != padding_config.commitment_length {
        return Err(ZkTlsnError::InvalidCommitmentLength {
            expected: padding_config.commitment_length,
            actual: committed_len,
        });
    }

    let committed_data = received_data[committed_range.clone()].to_vec();
    let blinder = secret.blinder.as_bytes().to_vec();

    tracing::debug!(
        "Committed data (fixed {} bytes): {:?}",
        committed_data.len(),
        String::from_utf8_lossy(&committed_data)
    );

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&committed_data);
    data_to_hash.extend_from_slice(&blinder);
    let committed_hash = blake3(&data_to_hash).map_err(|_| ZkTlsnError::HashVerificationFailed)?;

    let tlsnotary_hash = commitment.hash.value.as_bytes().to_vec();
    verify_hash(&committed_data, &blinder, &tlsnotary_hash)?;

    Ok(ProofInput {
        balance_committed_hash: committed_hash.to_vec(),
        balance_committed_part: committed_data,
        balance_blinder: blinder,
    })
}

fn validate_commitment(commitment: &PlaintextHash) -> Result<()> {
    if commitment.direction != Direction::Received {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }
    if commitment.hash.alg != HashAlgId::BLAKE3 {
        return Err(ZkTlsnError::InvalidHashAlgorithm);
    }
    Ok(())
}

fn validate_secret(secret: &PlaintextHashSecret) -> Result<()> {
    if secret.direction != Direction::Received {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }
    if secret.alg != HashAlgId::BLAKE3 {
        return Err(ZkTlsnError::InvalidHashAlgorithm);
    }
    Ok(())
}

fn verify_hash(balance: &[u8], blinder: &[u8], committed_hash: &[u8]) -> Result<()> {
    let computed_hash = blake3(&[balance, blinder].concat()).unwrap();

    if committed_hash != computed_hash.as_slice() {
        return Err(ZkTlsnError::HashVerificationFailed);
    }
    Ok(())
}

fn generate_zk_proof(proof_input: &ProofInput) -> Result<Proof> {
    tracing::info!("Generating ZK proof with Noir");

    let bytecode = load_circuit_bytecode()?;
    let (vk, proof) = create_proof(&bytecode, proof_input)?;

    tracing::info!("ZK proof generated successfully ({} bytes)", proof.len());
    Ok(Proof::new(vk, proof))
}

pub(crate) fn load_circuit_bytecode() -> Result<String> {
    const PROGRAM_JSON: &str = include_str!("../../target/circuit.json");
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    json["bytecode"]
        .as_str()
        .ok_or(ZkTlsnError::BytecodeNotFound)
        .map(String::from)
}

fn build_witness_inputs(proof_input: &ProofInput) -> Vec<String> {
    let mut inputs = Vec::new();
    inputs.extend(
        proof_input
            .balance_committed_hash
            .iter()
            .map(|b| b.to_string()),
    );
    inputs.extend(
        proof_input
            .balance_committed_part
            .iter()
            .map(|b| b.to_string()),
    );
    inputs.extend(proof_input.balance_blinder.iter().map(|b| b.to_string()));
    inputs
}

fn create_proof(bytecode: &str, proof_input: &ProofInput) -> Result<(Vec<u8>, Vec<u8>)> {
    let inputs = build_witness_inputs(proof_input);
    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();

    tracing::debug!("Creating witness map from inputs");
    let witness = from_vec_str_to_witness_map(input_refs).map_err(ZkTlsnError::NoirError)?;

    tracing::debug!("Setting up SRS from bytecode");
    setup_srs_from_bytecode(bytecode, None, false).map_err(ZkTlsnError::NoirError)?;

    tracing::debug!("Generating verification key");
    let vk = get_ultra_honk_verification_key(bytecode, false).map_err(ZkTlsnError::NoirError)?;

    tracing::debug!("Proving with UltraHonk");
    let proof =
        prove_ultra_honk(bytecode, witness, vk.clone(), false).map_err(ZkTlsnError::NoirError)?;

    Ok((vk, proof))
}
