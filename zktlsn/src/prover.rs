use noir::{
    barretenberg::{
        prove::{prove_ultra_honk, prove_ultra_honk_keccak},
        verify::{get_ultra_honk_keccak_verification_key, get_ultra_honk_verification_key},
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

const COMMITTED_PART_LEN: usize = 12;
const HONK_FIELD_BYTES: usize = 32;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeccakProof {
    pub verification_key: Vec<u8>,
    pub combined_proof: Vec<u8>,
    pub solidity_proof: Vec<u8>,
    pub public_inputs: Vec<[u8; HONK_FIELD_BYTES]>,
}

impl KeccakProof {
    pub fn public_inputs_hex(&self) -> Vec<String> {
        self.public_inputs
            .iter()
            .map(|word| format!("0x{}", hex_encode(word)))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementBundle {
    pub noir_inputs: NoirProverInputs,
    pub native_proof: Proof,
    pub keccak_proof: KeccakProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoirProverInputs {
    pub balance_committed_hash: [u8; 32],
    pub balance_committed_part: String,
    pub balance_blinder: [u8; 16],
}

impl NoirProverInputs {
    pub fn from_committed_part(
        balance_committed_part: impl Into<String>,
        balance_blinder: [u8; 16],
    ) -> Result<Self> {
        let balance_committed_part = balance_committed_part.into();
        let balance_bytes = balance_committed_part.as_bytes();
        if balance_bytes.len() != COMMITTED_PART_LEN {
            return Err(ZkTlsnError::InvalidInput(format!(
                "balance committed part must be {COMMITTED_PART_LEN} bytes, got {}",
                balance_bytes.len()
            )));
        }

        let mut hash_input = Vec::with_capacity(COMMITTED_PART_LEN + balance_blinder.len());
        hash_input.extend_from_slice(balance_bytes);
        hash_input.extend_from_slice(&balance_blinder);
        let committed_hash =
            blake3(&hash_input).map_err(|_| ZkTlsnError::HashVerificationFailed)?;

        Ok(Self {
            balance_committed_hash: to_fixed_array::<32>(
                &committed_hash,
                "balance_committed_hash",
            )?,
            balance_committed_part,
            balance_blinder,
        })
    }

    pub fn to_prover_toml(&self) -> String {
        format!(
            "balance_blinder = {}\nbalance_committed_hash = {}\nbalance_committed_part = \"{}\"\n",
            format_decimal_byte_array(&self.balance_blinder),
            format_decimal_byte_array(&self.balance_committed_hash),
            escape_toml_string(&self.balance_committed_part),
        )
    }

    pub fn to_solidity_public_inputs(&self) -> Vec<[u8; HONK_FIELD_BYTES]> {
        self.balance_committed_hash
            .iter()
            .map(|byte| {
                let mut word = [0u8; HONK_FIELD_BYTES];
                word[HONK_FIELD_BYTES - 1] = *byte;
                word
            })
            .collect()
    }

    fn witness_values(&self) -> Vec<String> {
        self.balance_committed_hash
            .iter()
            .chain(self.balance_committed_part.as_bytes().iter())
            .chain(self.balance_blinder.iter())
            .map(|byte| byte.to_string())
            .collect()
    }
}

pub fn generate_settlement_bundle(
    transcript_commitments: &[TranscriptCommitment],
    transcript_secrets: &[TranscriptSecret],
    received_data: &[u8],
    padding_config: PaddingConfig,
) -> Result<SettlementBundle> {
    let noir_inputs = derive_noir_prover_inputs(
        transcript_commitments,
        transcript_secrets,
        received_data,
        padding_config,
    )?;

    generate_settlement_bundle_from_inputs(noir_inputs)
}

pub fn generate_settlement_bundle_from_inputs(
    noir_inputs: NoirProverInputs,
) -> Result<SettlementBundle> {
    let native_proof = generate_native_proof_from_inputs(&noir_inputs)?;
    let keccak_proof = generate_keccak_proof_from_inputs(&noir_inputs)?;

    Ok(SettlementBundle {
        noir_inputs,
        native_proof,
        keccak_proof,
    })
}

fn generate_keccak_proof_from_inputs(input: &NoirProverInputs) -> Result<KeccakProof> {
    let bytecode = load_circuit_bytecode()?;
    let inputs = input.witness_values();
    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let witness = from_vec_str_to_witness_map(input_refs).map_err(ZkTlsnError::NoirError)?;

    let vk = get_ultra_honk_keccak_verification_key(&bytecode, false, false)
        .map_err(ZkTlsnError::NoirError)?;
    let combined_proof = prove_ultra_honk_keccak(&bytecode, witness, vk.clone(), false, false)
        .map_err(ZkTlsnError::NoirError)?;

    let expected_public_inputs = input.to_solidity_public_inputs();
    let public_inputs_size = expected_public_inputs.len() * HONK_FIELD_BYTES;
    if combined_proof.len() < public_inputs_size {
        return Err(ZkTlsnError::InvalidInput(format!(
            "combined keccak proof is too short: {} bytes, need at least {public_inputs_size}",
            combined_proof.len()
        )));
    }
    let parsed_public_inputs = combined_proof[..public_inputs_size]
        .chunks_exact(HONK_FIELD_BYTES)
        .map(|input| to_fixed_array::<HONK_FIELD_BYTES>(input, "solidity_public_input"))
        .collect::<Result<Vec<_>>>()?;

    if parsed_public_inputs != expected_public_inputs {
        return Err(ZkTlsnError::InvalidInput(
            "parsed Solidity public inputs do not match transcript-derived inputs".to_string(),
        ));
    }
    let solidity_proof = combined_proof[public_inputs_size..].to_vec();

    Ok(KeccakProof {
        verification_key: vk,
        combined_proof,
        solidity_proof,
        public_inputs: parsed_public_inputs,
    })
}

pub fn derive_noir_prover_inputs(
    transcript_commitments: &[TranscriptCommitment],
    transcript_secrets: &[TranscriptSecret],
    received_data: &[u8],
    padding_config: PaddingConfig,
) -> Result<NoirProverInputs> {
    let received_commitment = extract_received_commitment(transcript_commitments)?;
    let received_secret = extract_received_secret(transcript_secrets)?;
    let proof_input = prepare_proof_input(
        received_data,
        received_commitment,
        received_secret,
        padding_config,
    )?;

    build_noir_prover_inputs(&proof_input)
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

    let range_start = commitment.idx.min().ok_or_else(|| {
        ZkTlsnError::InvalidInput("received commitment is missing range start".to_string())
    })?;
    let range_end = commitment.idx.end().ok_or_else(|| {
        ZkTlsnError::InvalidInput("received commitment is missing range end".to_string())
    })?;
    if range_end < range_start {
        return Err(ZkTlsnError::InvalidInput(format!(
            "received commitment has invalid range: start={range_start}, end={range_end}"
        )));
    }
    let range = range_start..range_end;
    if range.len() != padding_config.commitment_length {
        return Err(ZkTlsnError::InvalidCommitmentLength {
            expected: padding_config.commitment_length,
            actual: range.len(),
        });
    }

    let committed_data = received_data
        .get(range.clone())
        .ok_or_else(|| {
            ZkTlsnError::InvalidInput(format!(
                "received commitment range {range_start}..{range_end} is out of transcript bounds {}",
                received_data.len()
            ))
        })?
        .to_vec();
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

fn generate_native_proof_from_inputs(input: &NoirProverInputs) -> Result<Proof> {
    let bytecode = load_circuit_bytecode()?;
    let inputs = input.witness_values();
    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();

    let witness = from_vec_str_to_witness_map(input_refs).map_err(ZkTlsnError::NoirError)?;
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(ZkTlsnError::NoirError)?;
    let proof =
        prove_ultra_honk(&bytecode, witness, vk.clone(), false).map_err(ZkTlsnError::NoirError)?;
    Ok(Proof::new(vk, proof))
}

fn build_noir_prover_inputs(input: &ProofInput) -> Result<NoirProverInputs> {
    let balance_committed_hash =
        to_fixed_array::<32>(&input.committed_hash, "balance_committed_hash")?;
    let balance_blinder = to_fixed_array::<16>(&input.blinder, "balance_blinder")?;
    let balance_committed_part =
        String::from_utf8(input.committed_data.clone()).map_err(|error| {
            ZkTlsnError::InvalidInput(format!(
                "balance committed part must be valid UTF-8: {error}"
            ))
        })?;

    Ok(NoirProverInputs {
        balance_committed_hash,
        balance_committed_part,
        balance_blinder,
    })
}

fn to_fixed_array<const N: usize>(bytes: &[u8], field_name: &str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        ZkTlsnError::InvalidInput(format!(
            "{field_name} must be {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn format_decimal_byte_array(bytes: &[u8]) -> String {
    let body = bytes
        .iter()
        .map(|byte| format!("\"{byte}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{body}]")
}

fn escape_toml_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => escaped.push(ch),
        }
    }

    escaped
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

#[cfg(test)]
mod unit_tests {
    use super::{COMMITTED_PART_LEN, NoirProverInputs};

    #[test]
    fn test_noir_prover_inputs_render_prover_toml() {
        let inputs = NoirProverInputs {
            balance_committed_hash: [7; 32],
            balance_committed_part: "100}        ".to_string(),
            balance_blinder: [9; 16],
        };

        let toml = inputs.to_prover_toml();

        assert!(toml.contains("balance_blinder = [\"9\", \"9\""));
        assert!(toml.contains("balance_committed_hash = [\"7\", \"7\""));
        assert!(toml.contains("balance_committed_part = \"100}        \""));
    }

    #[test]
    fn test_noir_prover_inputs_from_committed_part() {
        let inputs = NoirProverInputs::from_committed_part(
            "100}        ",
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .expect("inputs");

        assert_eq!(inputs.balance_committed_part.len(), COMMITTED_PART_LEN);
        assert_eq!(
            inputs.balance_committed_hash,
            [
                102, 226, 151, 18, 13, 110, 208, 205, 251, 132, 197, 47, 232, 53, 55, 231, 32, 250,
                42, 41, 183, 33, 127, 251, 95, 162, 46, 153, 230, 88, 152, 135,
            ]
        );
    }

    #[test]
    fn test_noir_prover_inputs_expand_to_solidity_public_inputs() {
        let inputs = NoirProverInputs {
            balance_committed_hash: [7; 32],
            balance_committed_part: "100}        ".to_string(),
            balance_blinder: [9; 16],
        };

        let public_inputs = inputs.to_solidity_public_inputs();
        assert_eq!(public_inputs.len(), 32);
        assert_eq!(public_inputs[0][31], 7);
        assert_eq!(public_inputs[31][31], 7);
    }

    #[test]
    fn test_expected_keccak_split_layout_is_prefix_based() {
        let inputs = NoirProverInputs::from_committed_part(
            "100}        ",
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .expect("inputs");
        let public_inputs = inputs.to_solidity_public_inputs();

        let mut combined = Vec::new();
        for public_input in &public_inputs {
            combined.extend_from_slice(public_input);
        }
        combined.extend_from_slice(&[0xabu8; 64]);

        let split_at = public_inputs.len() * 32;
        assert_eq!(split_at, 1024);
        assert_eq!(combined[..split_at].len(), 1024);
        assert_eq!(combined[split_at..].len(), 64);
        assert_eq!(combined[31], inputs.balance_committed_hash[0]);
        assert_eq!(combined[1023], inputs.balance_committed_hash[31]);
    }
}
