use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use flate2::{Compression, write::GzEncoder};
use noir::witness::{from_vec_str_to_witness_map, serialize_witness, witness_map_to_witness_stack};

use crate::{
    Result, ZkTlsnError, barretenberg_srs_cache_path_for, download_barretenberg_srs_to_cache_for,
    repo_root, setup_cached_barretenberg_srs_for,
};

pub const RECURSIVE_HONK_PROOF_FIELDS: usize = 457;
pub const RECURSIVE_HONK_VK_FIELDS: usize = 115;
pub const RECURSIVE_PUBLIC_INPUTS: usize = 6;
pub const INNER_PUBLIC_INPUTS: usize = 35;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveProofData {
    pub proof_fields: Vec<String>,
    pub public_inputs: Vec<String>,
    pub verification_key_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveState {
    pub total_amount: u64,
    pub transfers_root: [u8; 32],
    pub to_user_id: u64,
    pub allowed_null_vk_hash: [u8; 32],
    pub allowed_recursive_vk_hash: [u8; 32],
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

    pub fn srs_cache_path(self) -> PathBuf {
        barretenberg_srs_cache_path_for(self.name())
    }

    pub fn prepare_cached_srs(self) -> Result<PathBuf> {
        let path = download_barretenberg_srs_to_cache_for(self.name(), self.is_recursive())?;
        setup_cached_barretenberg_srs_for(self.name(), self.is_recursive())?;
        Ok(path)
    }

    pub fn is_recursive(self) -> bool {
        matches!(self, Self::Recursive)
    }
}

pub(crate) fn load_circuit_bytecode_from_target(circuit_name: &str) -> Result<String> {
    let path = repo_root()
        .join("target")
        .join(format!("{circuit_name}.json"));
    let json = fs::read_to_string(&path).map_err(|error| {
        ZkTlsnError::InvalidInput(format!("failed to read {}: {error}", path.display()))
    })?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    value["bytecode"]
        .as_str()
        .map(str::to_owned)
        .ok_or(ZkTlsnError::BytecodeNotFound)
}

pub fn write_witness_gzip(path: &Path, witness_values: &[String]) -> Result<()> {
    let witness_refs: Vec<&str> = witness_values.iter().map(String::as_str).collect();
    let witness_map = from_vec_str_to_witness_map(witness_refs).map_err(ZkTlsnError::NoirError)?;
    let witness_stack =
        witness_map_to_witness_stack(witness_map).map_err(ZkTlsnError::NoirError)?;
    let serialized = serialize_witness(witness_stack).map_err(ZkTlsnError::NoirError)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    std::io::Write::write_all(&mut encoder, &serialized)?;
    encoder.finish()?;

    Ok(())
}

pub fn parse_hex_field_word(value: &str) -> Result<[u8; 32]> {
    let hex = value.strip_prefix("0x").ok_or_else(|| {
        ZkTlsnError::InvalidInput(format!("field word must be 0x-prefixed, got `{value}`"))
    })?;
    if hex.len() != 64 {
        return Err(ZkTlsnError::InvalidInput(format!(
            "field word must contain 64 hex chars, got {}",
            hex.len()
        )));
    }

    let mut output = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Ok(output)
}

pub fn hex_field_words_to_bytes(words: &[String]) -> Result<Vec<[u8; 32]>> {
    words
        .iter()
        .map(|word| parse_hex_field_word(word))
        .collect()
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
