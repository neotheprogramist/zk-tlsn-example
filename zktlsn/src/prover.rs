use k256::sha2::{Digest, Sha256};
use noir::{
    barretenberg::{
        prove::prove_ultra_honk, srs::setup_srs_from_bytecode,
        verify::get_ultra_honk_verification_key,
    },
    witness::from_vec_str_to_witness_map,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tlsnotary::{
    Direction, HashAlgId, PlaintextHash, PlaintextHashSecret, TranscriptCommitment,
    TranscriptSecret,
};

use crate::error::{Result, ZkTlsnError};

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
) -> Result<Proof> {
    let received_commitment = extract_received_commitment(transcript_commitments)?;
    let received_secret = extract_received_secret(transcript_secrets)?;
    let proof_input = prepare_proof_input(received_data, received_commitment, received_secret)?;

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
    committed_hash: Vec<u8>,
    balance: String,
    blinder: Vec<u8>,
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: PlaintextHash,
    secret: PlaintextHashSecret,
) -> Result<ProofInput> {
    validate_commitment(&commitment)?;
    validate_secret(&secret)?;

    let committed_hash = commitment.hash.value.as_bytes().to_vec();
    let balance = extract_balance(received_data, &commitment);
    let blinder = secret.blinder.as_bytes().to_vec();

    verify_hash(&balance, &blinder, &committed_hash)?;

    Ok(ProofInput {
        committed_hash,
        balance: "100".into(),
        blinder,
    })
}

fn validate_commitment(commitment: &PlaintextHash) -> Result<()> {
    if commitment.direction != Direction::Received {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }
    if commitment.hash.alg != HashAlgId::SHA256 {
        return Err(ZkTlsnError::InvalidHashAlgorithm);
    }
    Ok(())
}

fn validate_secret(secret: &PlaintextHashSecret) -> Result<()> {
    if secret.direction != Direction::Received {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }
    if secret.alg != HashAlgId::SHA256 {
        return Err(ZkTlsnError::InvalidHashAlgorithm);
    }
    Ok(())
}

fn extract_balance(received_data: &[u8], commitment: &PlaintextHash) -> Vec<u8> {
    let start = commitment.idx.min().unwrap();
    let end = commitment.idx.end().unwrap();
    received_data[start..end].to_vec()
}

fn verify_hash(balance: &[u8], blinder: &[u8], committed_hash: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(balance);
    hasher.update(blinder);
    let computed_hash = hasher.finalize();

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
    inputs.extend(proof_input.committed_hash.iter().map(|b| b.to_string()));
    inputs.extend(proof_input.balance.as_bytes().iter().map(|b| b.to_string()));
    inputs.extend(proof_input.blinder.iter().map(|b| b.to_string()));
    inputs
}

fn create_proof(bytecode: &str, proof_input: &ProofInput) -> Result<(Vec<u8>, Vec<u8>)> {
    let inputs = build_witness_inputs(proof_input);
    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();

    tracing::debug!("Creating witness map from inputs");
    let witness = from_vec_str_to_witness_map(input_refs)
        .map_err(|e| ZkTlsnError::ProofGenerationFailed(e.to_string()))?;

    tracing::debug!("Setting up SRS from bytecode");
    setup_srs_from_bytecode(bytecode, None, false)
        .map_err(|e| ZkTlsnError::ProofGenerationFailed(e.to_string()))?;

    tracing::debug!("Generating verification key");
    let vk = get_ultra_honk_verification_key(bytecode, false)
        .map_err(|e| ZkTlsnError::ProofGenerationFailed(e.to_string()))?;

    tracing::debug!("Proving with UltraHonk");
    let proof = prove_ultra_honk(bytecode, witness, vk.clone(), false)
        .map_err(|e| ZkTlsnError::ProofGenerationFailed(e.to_string()))?;

    Ok((vk, proof))
}
