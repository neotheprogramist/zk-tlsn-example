use blake2::{Blake2s256, Digest};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use shared::{
    ATTESTATION_LEN, FiatTransferAttestation, encode_transfer_attestation,
    parse_transfer_attestation,
};
use tlsnotary::{
    Direction, HashAlgId, PlaintextHash, PlaintextHashSecret, TranscriptCommitment,
    TranscriptSecret,
};

use crate::{
    cli::{self, VerifierTarget},
    error::{Result, ZkTlsnError},
    padding::PaddingConfig,
    recursive::{HONK_FIELD_BYTES, RecursiveCircuit, field_word_hex},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub verification_key: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; HONK_FIELD_BYTES]>,
    #[serde(default)]
    pub vk_hash: [u8; HONK_FIELD_BYTES],
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
        self.public_inputs.iter().map(field_word_hex).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementBundle {
    pub noir_inputs: NoirProverInputs,
    pub native_proof: Proof,
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

        let committed_hash = blake3_hash(attestation_bytes, &attestation_blinder);
        Ok(Self {
            attestation_committed_hash: committed_hash,
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
    cli::compile_package(RecursiveCircuit::Attestation.name())?;
    let native_proof = generate_native_proof_from_inputs(&noir_inputs)?;
    Ok(SettlementBundle {
        noir_inputs,
        native_proof,
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

fn generate_native_proof_from_inputs(input: &NoirProverInputs) -> Result<Proof> {
    cli::write_package_prover_toml(
        RecursiveCircuit::Attestation.name(),
        &input.to_prover_toml(),
    )?;
    let witness_path = cli::execute_package(RecursiveCircuit::Attestation.name())?;
    let artifacts = cli::prove_circuit(
        RecursiveCircuit::Attestation,
        &witness_path,
        VerifierTarget::NoirRecursive,
    )?;

    Ok(Proof {
        verification_key: artifacts.verification_key,
        proof: artifacts.proof,
        public_inputs: artifacts.public_inputs,
        vk_hash: artifacts.vk_hash,
    })
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
            TranscriptSecret::Hash(secret) if secret.direction == Direction::Received => {
                Some(secret.clone())
            }
            _ => None,
        })
        .ok_or(ZkTlsnError::NoReceivedSecrets)
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: PlaintextHash,
    secret: PlaintextHashSecret,
    padding_config: PaddingConfig,
) -> Result<ProofInput> {
    if commitment.direction != Direction::Received {
        return Err(ZkTlsnError::InvalidCommitmentDirection);
    }
    if commitment.hash.alg != HashAlgId::BLAKE3 && commitment.hash.alg != HashAlgId::BLAKE2S {
        return Err(ZkTlsnError::InvalidHashAlgorithm);
    }

    let range_start = secret.idx.min().ok_or(ZkTlsnError::InvalidInput(
        "received secret commitment has empty index range".to_string(),
    ))?;
    let range_end = range_start.saturating_add(padding_config.commitment_length);
    let range = range_start..range_end;
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
    let committed_hash = commitment_hash(commitment.hash.alg, &committed_data, &blinder)?;
    if commitment.hash.value.as_bytes() != committed_hash {
        return Err(ZkTlsnError::HashVerificationFailed);
    }

    Ok(ProofInput {
        committed_hash: committed_hash.to_vec(),
        committed_data,
        blinder,
    })
}

fn commitment_hash(alg: HashAlgId, data: &[u8], blinder: &[u8]) -> Result<[u8; 32]> {
    match alg {
        HashAlgId::BLAKE3 => Ok(blake3_hash(data, blinder)),
        HashAlgId::BLAKE2S => Ok(blake2s_hash(data, blinder)),
        _ => Err(ZkTlsnError::InvalidHashAlgorithm),
    }
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

fn blake3_hash(data: &[u8], blinder: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.update(blinder);
    *hasher.finalize().as_bytes()
}

fn blake2s_hash(data: &[u8], blinder: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.update(blinder);
    hasher.finalize().into()
}

fn to_fixed_array<const N: usize>(bytes: &[u8], field_name: &str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        ZkTlsnError::InvalidInput(format!(
            "{field_name} must be {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn u64_to_field_word(value: u64) -> [u8; HONK_FIELD_BYTES] {
    let mut word = [0u8; HONK_FIELD_BYTES];
    word[HONK_FIELD_BYTES - 8..].copy_from_slice(&value.to_be_bytes());
    word
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
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04X}", u32::from(ch))),
            ch => escaped.push(ch),
        }
    }
    escaped
}

struct ProofInput {
    committed_hash: Vec<u8>,
    committed_data: Vec<u8>,
    blinder: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::NoirProverInputs;
    use crate::test_fixtures::{load_attestation_fixture, parse_fixture_public_inputs};

    #[test]
    fn noir_inputs_from_transfer_match_attestation_fixture() {
        let fixture = load_attestation_fixture();
        let attestation_blinder: [u8; 16] = fixture
            .attestation_blinder
            .clone()
            .try_into()
            .expect("fixture blinder length");
        let attestation_committed_hash: [u8; 32] = fixture
            .attestation_committed_hash
            .clone()
            .try_into()
            .expect("fixture committed hash length");

        let inputs = NoirProverInputs::from_transfer(
            fixture.tx_id,
            fixture.to_user_id,
            fixture.amount,
            attestation_blinder,
        )
        .expect("build Noir inputs");

        assert_eq!(inputs.attestation, fixture.attestation);
        assert_eq!(inputs.attestation_blinder, attestation_blinder);
        assert_eq!(
            inputs.attestation_committed_hash,
            attestation_committed_hash
        );
    }

    #[test]
    fn solidity_public_inputs_match_attestation_fixture() {
        let fixture = load_attestation_fixture();
        let attestation_blinder: [u8; 16] = fixture
            .attestation_blinder
            .clone()
            .try_into()
            .expect("fixture blinder length");
        let inputs = NoirProverInputs::from_transfer(
            fixture.tx_id,
            fixture.to_user_id,
            fixture.amount,
            attestation_blinder,
        )
        .expect("build Noir inputs");

        assert_eq!(
            inputs.to_solidity_public_inputs(),
            parse_fixture_public_inputs(&fixture.public_inputs)
        );
    }
}
