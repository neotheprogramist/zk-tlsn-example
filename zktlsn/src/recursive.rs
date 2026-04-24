use std::{fmt::Write as _, fs};

use serde::{Deserialize, Serialize};

use crate::{
    Result, ZkTlsnError,
    cli::{self, VerifierTarget, read_field_words_from_bytes},
    prover::{KeccakProof, Proof},
    repo_root,
};

pub(crate) const HONK_FIELD_BYTES: usize = 32;
pub(crate) const INNER_PUBLIC_INPUTS: usize = 35;
pub(crate) const NULL_PUBLIC_INPUTS: usize = 7;
pub const RECURSIVE_PUBLIC_INPUTS: usize = 7;

// bb 5.0 emits solidity verifiers with PAIRING_POINTS_SIZE=8 (was 16 in bb 4.x).
const PAIRING_POINTS_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaddingConfig {
    pub commitment_length: usize,
}

impl PaddingConfig {
    #[must_use]
    pub const fn new(commitment_length: usize) -> Self {
        Self { commitment_length }
    }
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self::new(10)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveState {
    pub total_amount: u64,
    pub transfers_root: [u8; 32],
    pub to_user_id: u64,
    pub null_vk_hash: [u8; 32],
    pub recursive_vk_hash: [u8; 32],
    pub inner_vk_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct VkArtifacts {
    pub verification_key: Vec<u8>,
    pub vk_hash: [u8; HONK_FIELD_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursiveCircuit {
    Attestation,
    Null,
    Recursive,
}

impl RecursiveCircuit {
    pub fn name(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::Null => "null",
            Self::Recursive => "recursive",
        }
    }

    pub fn bytecode_path(self) -> std::path::PathBuf {
        repo_root()
            .join("target")
            .join(format!("{}.json", self.name()))
    }

    pub fn prover_toml_path(self) -> std::path::PathBuf {
        repo_root()
            .join("circuits")
            .join(self.name())
            .join("Prover.toml")
    }

    pub fn public_input_count(self) -> usize {
        match self {
            Self::Attestation => INNER_PUBLIC_INPUTS,
            Self::Null => NULL_PUBLIC_INPUTS,
            Self::Recursive => RECURSIVE_PUBLIC_INPUTS,
        }
    }
}

pub fn compile_attestation_package() -> Result<()> {
    cli::compile_package(RecursiveCircuit::Attestation.name())
}

pub fn compile_all_packages() -> Result<()> {
    cli::compile_package(RecursiveCircuit::Attestation.name())?;
    cli::compile_package(RecursiveCircuit::Null.name())?;
    cli::compile_package(RecursiveCircuit::Recursive.name())
}

pub fn derive_circuit_vk(circuit: RecursiveCircuit) -> Result<VkArtifacts> {
    let (verification_key, vk_hash) =
        cli::write_vk_for_circuit(circuit, VerifierTarget::NoirRecursive)?;
    Ok(VkArtifacts {
        verification_key,
        vk_hash,
    })
}

fn prove_with_toml(
    circuit: RecursiveCircuit,
    prover_toml: &str,
    target: VerifierTarget,
) -> Result<cli::BbProofArtifacts> {
    cli::write_package_prover_toml(circuit.name(), prover_toml)?;
    let witness_path = cli::execute_package(circuit.name())?;
    cli::prove_circuit(circuit, &witness_path, target)
}

pub fn prove_null_circuit(
    to_user_id: u64,
    null_vk_hash: &[u8; HONK_FIELD_BYTES],
    recursive_vk_hash: &[u8; HONK_FIELD_BYTES],
    inner_vk_hash: &[u8; HONK_FIELD_BYTES],
) -> Result<Proof> {
    let prover_toml = format!(
        "to_user_id = \"{to_user_id}\"\n\
         allowed_null_vk_hash = \"{}\"\n\
         allowed_recursive_vk_hash = \"{}\"\n\
         allowed_inner_vk_hash = \"{}\"\n",
        field_word_hex(null_vk_hash),
        field_word_hex(recursive_vk_hash),
        field_word_hex(inner_vk_hash),
    );
    prove_noir_recursive_circuit(RecursiveCircuit::Null, &prover_toml)
}

pub fn prove_noir_recursive_circuit(circuit: RecursiveCircuit, prover_toml: &str) -> Result<Proof> {
    let artifacts = prove_with_toml(circuit, prover_toml, VerifierTarget::NoirRecursive)?;
    Ok(Proof {
        verification_key: artifacts.verification_key,
        proof: artifacts.proof,
        public_inputs: artifacts.public_inputs,
        vk_hash: artifacts.vk_hash,
    })
}

pub fn build_recursive_prover_toml(
    inner: &Proof,
    prev: &Proof,
    null_vk_hash: &[u8; HONK_FIELD_BYTES],
    recursive_vk_hash: &[u8; HONK_FIELD_BYTES],
    inner_vk_hash: &[u8; HONK_FIELD_BYTES],
) -> Result<String> {
    let inner_proof_fields = read_field_words_from_bytes(&inner.proof, "inner proof")?;
    let inner_vk_fields = read_field_words_from_bytes(&inner.verification_key, "inner vk")?;
    let prev_proof_fields = read_field_words_from_bytes(&prev.proof, "prev proof")?;
    let prev_vk_fields = read_field_words_from_bytes(&prev.verification_key, "prev vk")?;

    Ok(format!(
        "inner_vk = {}\n\
         inner_proof = {}\n\
         inner_public_inputs = {}\n\
         inner_key_hash = \"{}\"\n\
         prev_vk = {}\n\
         prev_proof = {}\n\
         prev_public_inputs = {}\n\
         prev_key_hash = \"{}\"\n\
         allowed_null_vk_hash = \"{}\"\n\
         allowed_recursive_vk_hash = \"{}\"\n\
         allowed_inner_vk_hash = \"{}\"\n",
        format_field_array(&inner_vk_fields),
        format_field_array(&inner_proof_fields),
        format_field_array(&inner.public_inputs),
        field_word_hex(&inner.vk_hash),
        format_field_array(&prev_vk_fields),
        format_field_array(&prev_proof_fields),
        format_field_array(&prev.public_inputs),
        field_word_hex(&prev.vk_hash),
        field_word_hex(null_vk_hash),
        field_word_hex(recursive_vk_hash),
        field_word_hex(inner_vk_hash),
    ))
}

pub fn prove_keccak_circuit(circuit: RecursiveCircuit, prover_toml: &str) -> Result<KeccakProof> {
    let artifacts = prove_with_toml(circuit, prover_toml, VerifierTarget::Evm)?;
    let combined_proof = [
        cli::flatten_public_inputs(&artifacts.public_inputs),
        artifacts.proof.clone(),
    ]
    .concat();

    Ok(KeccakProof {
        verification_key: artifacts.verification_key,
        combined_proof,
        solidity_proof: artifacts.proof,
        public_inputs: artifacts.public_inputs,
    })
}

pub fn generate_honk_solidity_verifier(
    verification_key: &[u8],
    contract_name: &str,
) -> Result<String> {
    let output_dir = repo_root().join("target/generated-verifier");
    fs::create_dir_all(&output_dir)?;
    let vk_path = output_dir.join("vk");
    let verifier_path = output_dir.join("Verifier.sol");
    fs::write(&vk_path, verification_key)?;
    cli::write_solidity_verifier(&vk_path, &verifier_path, VerifierTarget::Evm)?;
    let source = fs::read_to_string(&verifier_path)?;
    Ok(source.replacen(
        "contract HonkVerifier is",
        &format!("contract {contract_name} is"),
        1,
    ))
}

pub fn state_from_public_inputs(public_inputs: &[String]) -> Result<RecursiveState> {
    if public_inputs.len() != RECURSIVE_PUBLIC_INPUTS {
        return Err(ZkTlsnError::InvalidInput {
            context: "settlement public inputs",
            details: format!(
                "expected {RECURSIVE_PUBLIC_INPUTS} values, got {}",
                public_inputs.len()
            ),
        });
    }

    Ok(RecursiveState {
        total_amount: field_word_to_u64(&public_inputs[1])?,
        transfers_root: parse_hex_field_word(&public_inputs[2])?,
        to_user_id: field_word_to_u64(&public_inputs[3])?,
        null_vk_hash: parse_hex_field_word(&public_inputs[4])?,
        recursive_vk_hash: parse_hex_field_word(&public_inputs[5])?,
        inner_vk_hash: parse_hex_field_word(&public_inputs[6])?,
    })
}

pub(crate) fn parse_hex_field_word(value: &str) -> Result<[u8; HONK_FIELD_BYTES]> {
    let hex = value.strip_prefix("0x").ok_or(ZkTlsnError::InvalidInput {
        context: "field word",
        details: format!("must be 0x-prefixed, got `{value}`"),
    })?;
    if hex.len() != HONK_FIELD_BYTES * 2 {
        return Err(ZkTlsnError::InvalidInput {
            context: "field word",
            details: format!(
                "must contain {} hex chars, got {}",
                HONK_FIELD_BYTES * 2,
                hex.len()
            ),
        });
    }

    let mut output = [0u8; HONK_FIELD_BYTES];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Ok(output)
}

pub(crate) fn field_word_to_u64(value: &str) -> Result<u64> {
    let bytes = parse_hex_field_word(value)?;
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(ZkTlsnError::InvalidInput {
            context: "field word",
            details: format!("does not fit into u64: {value}"),
        });
    }
    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(value_bytes))
}

pub(crate) fn field_word_hex(word: &[u8; HONK_FIELD_BYTES]) -> String {
    let mut encoded = String::from("0x");
    for byte in word {
        // PROOF: std::fmt::Write for String never returns Err.
        write!(&mut encoded, "{byte:02x}").expect("write to String is infallible");
    }
    encoded
}

fn format_field_array(words: &[[u8; HONK_FIELD_BYTES]]) -> String {
    let values = words
        .iter()
        .map(|word| format!("\"{}\"", field_word_hex(word)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ZkTlsnError::InvalidInput {
            context: "hex nibble",
            details: format!("invalid character `{}`", char::from(byte)),
        }),
    }
}

pub fn validate_generated_solidity_verifier(source: &str, num_public_inputs: usize) -> Result<()> {
    let expected_public_inputs = num_public_inputs + PAIRING_POINTS_SIZE;
    [
        (
            format!("uint256 constant NUMBER_OF_PUBLIC_INPUTS = {expected_public_inputs};"),
            "verifier constant `NUMBER_OF_PUBLIC_INPUTS`",
        ),
        (
            format!("publicInputsSize: uint256({expected_public_inputs})"),
            "verification key `publicInputsSize`",
        ),
        (
            String::from(
                "require(publicInputs.length == vk.publicInputsSize - PAIRING_POINTS_SIZE, Errors.PublicInputsLengthWrong());",
            ),
            "public input arity guard",
        ),
        (
            String::from(
                "function verify(bytes calldata _proof, bytes32[] calldata _publicInputs)",
            ),
            "verifier interface",
        ),
    ]
    .into_iter()
    .try_for_each(|(snippet, label)| ensure_contains(source, &snippet, label))
}

fn ensure_contains(source: &str, snippet: &str, label: &'static str) -> Result<()> {
    source
        .contains(snippet)
        .then_some(())
        .ok_or_else(|| ZkTlsnError::InvalidInput {
            context: "solidity verifier",
            details: format!("missing {label}: `{snippet}`"),
        })
}
