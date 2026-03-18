use std::{fmt::Write as _, fs, path::PathBuf};

use crate::{
    Result, TicketSigner, ZkTlsnError,
    cli::{self, VerifierTarget},
    prover::KeccakProof,
    repo_root,
};

pub const HONK_FIELD_BYTES: usize = 32;
pub const INNER_PUBLIC_INPUTS: usize = 35;
pub const NULL_PUBLIC_INPUTS: usize = 6;
pub const RECURSIVE_PUBLIC_INPUTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveState {
    pub total_amount: u64,
    pub transfers_root: [u8; 32],
    pub to_user_id: u64,
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

    pub fn bytecode_path(self) -> PathBuf {
        repo_root()
            .join("target")
            .join(format!("{}.json", self.name()))
    }

    pub fn prover_toml_path(self) -> PathBuf {
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

pub fn compile_recursive_package() -> Result<()> {
    cli::compile_package(RecursiveCircuit::Recursive.name())
}

pub fn write_recursive_constants() -> Result<()> {
    let signer = TicketSigner::from_env_or_default()?;
    let (pubkey_x, pubkey_y) = signer.public_key_coordinates()?;
    let padding_ticket = signer.sign_padding_ticket()?;
    let padding_signature = padding_ticket.signature_array()?;
    let contents = format!(
        "pub global TICKET_SIGNER_PUBKEY_X: [u8; 32] = {};\n\
pub global TICKET_SIGNER_PUBKEY_Y: [u8; 32] = {};\n\
pub global PADDING_SIGNATURE: [u8; 64] = {};\n",
        format_byte_array(&pubkey_x),
        format_byte_array(&pubkey_y),
        format_byte_array(&padding_signature),
    );
    fs::write(
        repo_root().join("circuits/recursive/src/generated_constants.nr"),
        contents,
    )?;
    Ok(())
}

pub fn sync_recursive_circuit() -> Result<()> {
    write_recursive_constants()?;
    compile_recursive_package()
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
        total_amount: field_word_to_u64(&public_inputs[0])?,
        transfers_root: parse_hex_field_word(&public_inputs[1])?,
        to_user_id: field_word_to_u64(&public_inputs[2])?,
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

fn format_byte_array<const N: usize>(bytes: &[u8; N]) -> String {
    let values = bytes
        .iter()
        .map(u8::to_string)
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
            byte as char
        ))),
    }
}

#[allow(dead_code)]
pub(crate) fn field_word_hex(word: &[u8; HONK_FIELD_BYTES]) -> String {
    let mut encoded = String::from("0x");
    for byte in word {
        write!(&mut encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use crate::test_fixtures::{
        load_settlement_fixture, load_settlement_public_inputs_from_fixture,
    };

    use super::{
        INNER_PUBLIC_INPUTS, NULL_PUBLIC_INPUTS, RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit,
        field_word_hex, field_word_to_u64, state_from_public_inputs,
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
                .contains("expected 3 settlement public inputs")
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
