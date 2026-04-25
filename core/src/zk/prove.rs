use blake3::Hasher;
use serde::{Deserialize, Serialize};
use tlsn::{
    hash::HashAlgId,
    transcript::{
        Direction, TranscriptCommitment, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
};

use crate::{
    attestation::{
        ATTESTATION_LEN, FiatTransferAttestation, encode_transfer_attestation,
        parse_transfer_attestation,
    },
    error::{Error, Result},
    zk::{
        cli::{self, VerifierTarget},
        recursive::{
            HONK_FIELD_BYTES, PaddingConfig, RecursiveCircuit, field_word_hex, field_word_to_u64,
        },
    },
};

const COMMITTED_HASH_BYTES: usize = 32;
const TX_ID_INDEX: usize = 32;
const TO_USER_ID_INDEX: usize = 33;
const AMOUNT_INDEX: usize = 34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofTransferFields {
    pub tx_id: u64,
    pub to_user_id: u64,
    pub amount: u64,
}

pub fn extract_committed_hash_from_proof(proof: &Proof) -> Result<[u8; COMMITTED_HASH_BYTES]> {
    if proof.public_inputs.len() < COMMITTED_HASH_BYTES {
        return Err(Error::InvalidInput {
            context: "proof public inputs",
            details: format!(
                "expected at least {COMMITTED_HASH_BYTES}, got {}",
                proof.public_inputs.len()
            ),
        });
    }

    proof
        .public_inputs
        .iter()
        .take(COMMITTED_HASH_BYTES)
        .enumerate()
        .try_fold([0u8; COMMITTED_HASH_BYTES], |mut hash, (index, field)| {
            if field[..HONK_FIELD_BYTES - 1].iter().any(|&byte| byte != 0) {
                return Err(Error::InvalidInput {
                    context: "commitment byte",
                    details: format!("public input {index} does not fit into a byte"),
                });
            }
            hash[index] = field[HONK_FIELD_BYTES - 1];
            Ok(hash)
        })
}

pub fn extract_transfer_fields_from_proof(proof: &Proof) -> Result<ProofTransferFields> {
    let get_field = |index: usize, name: &'static str| -> Result<&[u8; HONK_FIELD_BYTES]> {
        proof.public_inputs.get(index).ok_or(Error::InvalidInput {
            context: name,
            details: format!(
                "proof public inputs too short: need index {index}, got length {}",
                proof.public_inputs.len()
            ),
        })
    };

    Ok(ProofTransferFields {
        tx_id: field_word_to_u64(&field_word_hex(get_field(TX_ID_INDEX, "tx_id")?))?,
        to_user_id: field_word_to_u64(&field_word_hex(get_field(TO_USER_ID_INDEX, "to_user_id")?))?,
        amount: field_word_to_u64(&field_word_hex(get_field(AMOUNT_INDEX, "amount")?))?,
    })
}

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
pub struct AttestationProof {
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
            encode_transfer_attestation(FiatTransferAttestation::new(tx_id, to_user_id, amount))?;

        Self::from_attestation(attestation, attestation_blinder)
    }

    pub fn from_attestation(
        attestation: impl Into<String>,
        attestation_blinder: [u8; 16],
    ) -> Result<Self> {
        let attestation = attestation.into();
        let parsed = parse_transfer_attestation(&attestation)?;
        let attestation_bytes = attestation.as_bytes();
        if attestation_bytes.len() != ATTESTATION_LEN {
            return Err(Error::InvalidInput {
                context: "attestation length",
                details: format!(
                    "expected {ATTESTATION_LEN} bytes, got {}",
                    attestation_bytes.len()
                ),
            });
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

pub fn prove_attestation(
    transcript_commitments: &[TranscriptCommitment],
    transcript_secrets: &[TranscriptSecret],
    received_data: &[u8],
    padding_config: PaddingConfig,
) -> Result<AttestationProof> {
    let noir_inputs = derive_noir_prover_inputs(
        transcript_commitments,
        transcript_secrets,
        received_data,
        padding_config,
    )?;
    prove_attestation_from_inputs(noir_inputs)
}

pub fn prove_attestation_from_inputs(noir_inputs: NoirProverInputs) -> Result<AttestationProof> {
    cli::compile_package(RecursiveCircuit::Attestation.name())?;
    let native_proof = generate_native_proof_from_inputs(&noir_inputs)?;
    Ok(AttestationProof {
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
        .ok_or(Error::NoReceivedCommitments)
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
        .ok_or(Error::NoReceivedSecrets)
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: PlaintextHash,
    secret: PlaintextHashSecret,
    padding_config: PaddingConfig,
) -> Result<ProofInput> {
    if commitment.direction != Direction::Received {
        return Err(Error::InvalidCommitmentDirection);
    }
    if commitment.hash.alg != HashAlgId::BLAKE3 {
        return Err(Error::InvalidHashAlgorithm);
    }

    let range_start = secret.idx.min().ok_or(Error::InvalidInput {
        context: "received secret",
        details: String::from("commitment has empty index range"),
    })?;
    let range_end = range_start.saturating_add(padding_config.commitment_length);
    let range = range_start..range_end;
    let committed_data = received_data
        .get(range.clone())
        .ok_or_else(|| Error::InvalidInput {
            context: "received commitment range",
            details: format!(
                "{range_start}..{range_end} exceeds transcript length {}",
                received_data.len()
            ),
        })?
        .to_vec();
    let blinder = secret.blinder.as_bytes().to_vec();
    let committed_hash = blake3_hash(&committed_data, &blinder);
    if commitment.hash.value.as_bytes() != committed_hash {
        return Err(Error::HashVerificationFailed);
    }

    Ok(ProofInput {
        committed_hash: committed_hash.to_vec(),
        committed_data,
        blinder,
    })
}

fn build_noir_prover_inputs(input: &ProofInput) -> Result<NoirProverInputs> {
    let attestation_committed_hash =
        to_fixed_array::<32>(&input.committed_hash, "attestation_committed_hash")?;
    let attestation_blinder = to_fixed_array::<16>(&input.blinder, "attestation_blinder")?;
    let attestation = String::from_utf8(input.committed_data.clone())?;
    let parsed = parse_transfer_attestation(&attestation)?;

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

fn to_fixed_array<const N: usize>(bytes: &[u8], field_name: &'static str) -> Result<[u8; N]> {
    let Ok(array) = <[u8; N]>::try_from(bytes) else {
        return Err(Error::InvalidInput {
            context: field_name,
            details: format!("expected {N} bytes, got {}", bytes.len()),
        });
    };
    Ok(array)
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
