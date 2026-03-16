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
use shared::{
    ATTESTATION_LEN, FiatTransferAttestation, encode_transfer_attestation,
    parse_transfer_attestation,
};
use tlsnotary::{
    Direction, HashAlgId, PlaintextHash, PlaintextHashSecret, TranscriptCommitment,
    TranscriptSecret,
};

use crate::{
    error::{Result, ZkTlsnError},
    padding::PaddingConfig,
};

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
    pub attestation_committed_hash: [u8; 32],
    pub tx_id: u64,
    pub to_user_id: u64,
    pub amount: u64,
    pub attestation: String,
    pub attestation_blinder: [u8; 16],
}

impl NoirProverInputs {
    pub fn from_transfer(
        tx_id: u64,
        to_user_id: u64,
        amount: u64,
        attestation_blinder: [u8; 16],
    ) -> Result<Self> {
        let attestation =
            encode_transfer_attestation(FiatTransferAttestation::new(tx_id, to_user_id, amount))
                .map_err(|error| ZkTlsnError::InvalidInput(error.to_string()))?;

        Self::from_attestation(attestation, attestation_blinder)
    }

    pub fn from_attestation(
        attestation: impl Into<String>,
        attestation_blinder: [u8; 16],
    ) -> Result<Self> {
        let attestation = attestation.into();
        let parsed = parse_transfer_attestation(&attestation)
            .map_err(|error| ZkTlsnError::InvalidInput(error.to_string()))?;
        let attestation_bytes = attestation.as_bytes();
        if attestation_bytes.len() != ATTESTATION_LEN {
            return Err(ZkTlsnError::InvalidInput(format!(
                "attestation must be {ATTESTATION_LEN} bytes, got {}",
                attestation_bytes.len()
            )));
        }

        let hash_input = [attestation_bytes, &attestation_blinder].concat();
        let committed_hash =
            blake3(&hash_input).map_err(|_| ZkTlsnError::HashVerificationFailed)?;

        Ok(Self {
            attestation_committed_hash: to_fixed_array::<32>(
                &committed_hash,
                "attestation_committed_hash",
            )?,
            tx_id: parsed.tx_id,
            to_user_id: parsed.to_user_id,
            amount: parsed.amount,
            attestation,
            attestation_blinder,
        })
    }

    pub fn to_prover_toml(&self) -> String {
        format!(
            "attestation_blinder = {}\nattestation_committed_hash = {}\ntx_id = \"{}\"\nto_user_id = \"{}\"\namount = \"{}\"\nattestation = \"{}\"\n",
            format_decimal_byte_array(&self.attestation_blinder),
            format_decimal_byte_array(&self.attestation_committed_hash),
            self.tx_id,
            self.to_user_id,
            self.amount,
            escape_toml_string(&self.attestation),
        )
    }

    pub fn to_solidity_public_inputs(&self) -> Vec<[u8; HONK_FIELD_BYTES]> {
        self.attestation_committed_hash
            .iter()
            .map(|byte| {
                let mut word = [0u8; HONK_FIELD_BYTES];
                word[HONK_FIELD_BYTES - 1] = *byte;
                word
            })
            .chain(
                [self.tx_id, self.to_user_id, self.amount]
                    .into_iter()
                    .map(u64_to_field_word),
            )
            .collect()
    }

    fn witness_values(&self) -> Vec<String> {
        self.attestation_committed_hash
            .iter()
            .map(|byte| byte.to_string())
            .chain(
                [self.tx_id, self.to_user_id, self.amount]
                    .into_iter()
                    .map(|value| value.to_string()),
            )
            .chain(
                self.attestation
                    .as_bytes()
                    .iter()
                    .map(|byte| byte.to_string()),
            )
            .chain(self.attestation_blinder.iter().map(|byte| byte.to_string()))
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
        .map(|value| to_fixed_array::<HONK_FIELD_BYTES>(value, "solidity_public_input"))
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
    let attestation_committed_hash =
        to_fixed_array::<32>(&input.committed_hash, "attestation_committed_hash")?;
    let attestation_blinder = to_fixed_array::<16>(&input.blinder, "attestation_blinder")?;
    let attestation = String::from_utf8(input.committed_data.clone()).map_err(|error| {
        ZkTlsnError::InvalidInput(format!("attestation must be valid UTF-8: {error}"))
    })?;
    let parsed = parse_transfer_attestation(&attestation)
        .map_err(|error| ZkTlsnError::InvalidInput(error.to_string()))?;

    Ok(NoirProverInputs {
        attestation_committed_hash,
        tx_id: parsed.tx_id,
        to_user_id: parsed.to_user_id,
        amount: parsed.amount,
        attestation,
        attestation_blinder,
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

fn u64_to_field_word(value: u64) -> [u8; HONK_FIELD_BYTES] {
    let mut word = [0u8; HONK_FIELD_BYTES];
    word[HONK_FIELD_BYTES - 8..].copy_from_slice(&value.to_be_bytes());
    word
}

#[cfg(test)]
mod unit_tests {
    use shared::ATTESTATION_LEN;

    use super::{NoirProverInputs, u64_to_field_word};

    #[test]
    fn test_noir_prover_inputs_render_prover_toml() {
        let inputs = NoirProverInputs::from_transfer(
            1,
            3,
            25,
            [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
        )
        .expect("inputs");

        let toml = inputs.to_prover_toml();

        assert!(toml.contains("attestation_blinder = [\"9\", \"9\""));
        assert!(toml.contains("attestation_committed_hash = [\""));
        assert!(toml.contains("tx_id = \"1\""));
        assert!(toml.contains("to_user_id = \"3\""));
        assert!(toml.contains("amount = \"25\""));
    }

    #[test]
    fn test_noir_prover_inputs_from_transfer() {
        let inputs = NoirProverInputs::from_transfer(
            1,
            3,
            25,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .expect("inputs");

        assert_eq!(inputs.attestation.len(), ATTESTATION_LEN);
        assert_eq!(inputs.tx_id, 1);
        assert_eq!(inputs.to_user_id, 3);
        assert_eq!(inputs.amount, 25);
    }

    #[test]
    fn test_noir_prover_inputs_expand_to_solidity_public_inputs() {
        let inputs = NoirProverInputs::from_transfer(
            1,
            3,
            25,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .expect("inputs");

        let public_inputs = inputs.to_solidity_public_inputs();
        assert_eq!(public_inputs.len(), 35);
        assert_eq!(public_inputs[0][31], inputs.attestation_committed_hash[0]);
        assert_eq!(public_inputs[31][31], inputs.attestation_committed_hash[31]);
        assert_eq!(public_inputs[32], u64_to_field_word(1));
        assert_eq!(public_inputs[33], u64_to_field_word(3));
        assert_eq!(public_inputs[34], u64_to_field_word(25));
    }

    #[test]
    fn test_expected_keccak_split_layout_is_prefix_based() {
        let inputs = NoirProverInputs::from_transfer(
            1,
            3,
            25,
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
        assert_eq!(split_at, 1120);
        assert_eq!(combined[..split_at].len(), 1120);
        assert_eq!(combined[split_at..].len(), 64);
        assert_eq!(combined[31], inputs.attestation_committed_hash[0]);
        assert_eq!(combined[1023], inputs.attestation_committed_hash[31]);
        assert_eq!(combined[1055], 1);
        assert_eq!(combined[1087], 3);
        assert_eq!(combined[1119], 25);
    }
}
