use std::{fmt::Write as _, fs};

use crate::{
    Result, ZkTlsnError,
    cli::{self, VerifierTarget, read_field_words_from_bytes},
    prover::{KeccakProof, Proof},
    repo_root,
};

pub const HONK_FIELD_BYTES: usize = 32;
pub const INNER_PUBLIC_INPUTS: usize = 35;
pub const NULL_PUBLIC_INPUTS: usize = 7;
pub const RECURSIVE_PUBLIC_INPUTS: usize = 7;

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

    cli::write_package_prover_toml(RecursiveCircuit::Null.name(), &prover_toml)?;
    let witness_path = cli::execute_package(RecursiveCircuit::Null.name())?;
    let artifacts = cli::prove_circuit(
        RecursiveCircuit::Null,
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

pub fn prove_noir_recursive_circuit(circuit: RecursiveCircuit, prover_toml: &str) -> Result<Proof> {
    cli::write_package_prover_toml(circuit.name(), prover_toml)?;
    let witness_path = cli::execute_package(circuit.name())?;
    let artifacts = cli::prove_circuit(circuit, &witness_path, VerifierTarget::NoirRecursive)?;

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
    cli::write_package_prover_toml(circuit.name(), prover_toml)?;
    let witness_path = cli::execute_package(circuit.name())?;
    let artifacts = cli::prove_circuit(circuit, &witness_path, VerifierTarget::Evm)?;
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
        return Err(ZkTlsnError::InvalidInput(format!(
            "expected {RECURSIVE_PUBLIC_INPUTS} settlement public inputs, got {}",
            public_inputs.len()
        )));
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

pub fn parse_hex_field_word(value: &str) -> Result<[u8; HONK_FIELD_BYTES]> {
    let hex = value.strip_prefix("0x").ok_or_else(|| {
        ZkTlsnError::InvalidInput(format!("field word must be 0x-prefixed, got `{value}`"))
    })?;
    if hex.len() != HONK_FIELD_BYTES * 2 {
        return Err(ZkTlsnError::InvalidInput(format!(
            "field word must contain {} hex chars, got {}",
            HONK_FIELD_BYTES * 2,
            hex.len()
        )));
    }

    let mut output = [0u8; HONK_FIELD_BYTES];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Ok(output)
}

pub fn hex_field_words_to_bytes(words: &[String]) -> Result<Vec<[u8; HONK_FIELD_BYTES]>> {
    words
        .iter()
        .map(|word| parse_hex_field_word(word))
        .collect()
}

pub fn field_word_to_u64(value: &str) -> Result<u64> {
    let bytes = parse_hex_field_word(value)?;
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(ZkTlsnError::InvalidInput(format!(
            "field word does not fit into u64: {value}"
        )));
    }
    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(value_bytes))
}

pub(crate) fn field_word_hex(word: &[u8; HONK_FIELD_BYTES]) -> String {
    let mut encoded = String::from("0x");
    for byte in word {
        // write! to String is infallible per std::fmt::Write impl for String
        write!(&mut encoded, "{byte:02x}").expect("write to string");
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
        _ => Err(ZkTlsnError::InvalidInput(format!(
            "invalid hex character `{}`",
            char::from(byte)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        INNER_PUBLIC_INPUTS, NULL_PUBLIC_INPUTS, RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit,
        field_word_hex, field_word_to_u64, state_from_public_inputs,
    };
    use crate::test_fixtures::{
        load_settlement_fixture, load_settlement_public_inputs_from_fixture,
    };

    #[test]
    fn recursive_circuit_names_match_workspace_packages() {
        assert_eq!(RecursiveCircuit::Attestation.name(), "attestation");
        assert_eq!(RecursiveCircuit::Null.name(), "null");
        assert_eq!(RecursiveCircuit::Recursive.name(), "recursive");
    }

    #[test]
    fn recursive_circuit_public_input_counts_match_expected_shapes() {
        assert_eq!(
            RecursiveCircuit::Attestation.public_input_count(),
            INNER_PUBLIC_INPUTS
        );
        assert_eq!(
            RecursiveCircuit::Null.public_input_count(),
            NULL_PUBLIC_INPUTS
        );
        assert_eq!(
            RecursiveCircuit::Recursive.public_input_count(),
            RECURSIVE_PUBLIC_INPUTS
        );
    }

    #[test]
    fn settlement_fixture_public_inputs_parse_exactly() {
        let fixture = load_settlement_fixture();

        let state =
            state_from_public_inputs(&fixture.public_inputs).expect("parse settlement state");
        assert_eq!(state.total_amount, fixture.total_amount);
        assert_eq!(
            field_word_hex(&state.transfers_root),
            fixture.transfers_root
        );
        assert_eq!(state.to_user_id, fixture.to_user_id);
        assert_eq!(field_word_hex(&state.null_vk_hash), fixture.null_vk_hash);
        assert_eq!(
            field_word_hex(&state.recursive_vk_hash),
            fixture.recursive_vk_hash
        );
        assert_eq!(field_word_hex(&state.inner_vk_hash), fixture.inner_vk_hash);
    }

    #[test]
    fn settlement_fixture_binary_public_inputs_roundtrip_to_state() {
        let fixture = load_settlement_fixture();
        let hex_words = load_settlement_public_inputs_from_fixture()
            .iter()
            .map(field_word_hex)
            .collect::<Vec<_>>();

        let state = state_from_public_inputs(&hex_words).expect("parse settlement state");
        assert_eq!(state.total_amount, fixture.total_amount);
        assert_eq!(
            field_word_hex(&state.transfers_root),
            fixture.transfers_root
        );
        assert_eq!(state.to_user_id, fixture.to_user_id);
    }

    #[test]
    fn settlement_state_rejects_wrong_arity() {
        let error = state_from_public_inputs(&["0x00".to_string()])
            .expect_err("wrong public input count should fail");
        assert!(
            error
                .to_string()
                .contains("expected 7 settlement public inputs")
        );
    }

    #[test]
    fn field_word_to_u64_rejects_non_u64_values() {
        let error =
            field_word_to_u64("0x0100000000000000000000000000000000000000000000000000000000000000")
                .expect_err("oversized field word should fail");
        assert!(error.to_string().contains("does not fit into u64"));
    }
}
