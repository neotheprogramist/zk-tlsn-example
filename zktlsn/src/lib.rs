mod commitment;
mod error;
mod padding;
mod proof;
mod prover;
mod recursive;
mod verifier;

#[cfg(test)]
mod tests;

use std::{
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};

pub use commitment::{BoundCommitment, bind_commitments_to_keys};
pub use error::{Result, ZkTlsnError};
use noir::barretenberg::{
    srs::{get_srs, localsrs::LocalSrs, setup_srs_from_bytecode},
    utils::get_subgroup_size,
};
pub use padding::PaddingConfig;
pub use proof::{extract_committed_hash_from_proof, verify_proof, verify_proof_against_hash};
pub use prover::{
    KeccakProof, NoirProverInputs, Proof, SettlementBundle, derive_noir_prover_inputs,
    generate_settlement_bundle, generate_settlement_bundle_from_inputs,
};
pub use recursive::{
    INNER_PUBLIC_INPUTS, RECURSIVE_HONK_PROOF_FIELDS, RECURSIVE_HONK_VK_FIELDS,
    RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit, RecursiveProofData, RecursiveState,
    hex_field_words_to_bytes, parse_hex_field_word, write_witness_gzip,
};
pub use verifier::{
    validate_generated_solidity_verifier, validate_generated_solidity_verifier_for_bytecode,
};

const SRS_CACHE_DIR: &str = "srs_cache";
const ATTESTATION_SRS_FILE: &str = "attestation.srs";

pub(crate) fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zktlsn crate should live under the workspace root")
}

fn cached_srs_path_string(circuit_name: &str) -> Result<String> {
    let path = barretenberg_srs_cache_path_for(circuit_name);
    path.to_str().map(str::to_owned).ok_or_else(|| {
        ZkTlsnError::InvalidInput(format!("invalid UTF-8 SRS path: {}", path.display()))
    })
}

pub fn barretenberg_srs_cache_path() -> PathBuf {
    barretenberg_srs_cache_path_for("attestation")
}

pub fn barretenberg_srs_cache_path_for(circuit_name: &str) -> PathBuf {
    let file_name = match circuit_name {
        "attestation" => ATTESTATION_SRS_FILE.to_string(),
        name => format!("{name}.srs"),
    };
    repo_root().join(SRS_CACHE_DIR).join(file_name)
}

pub fn download_barretenberg_srs_to_cache() -> Result<PathBuf> {
    download_barretenberg_srs_to_cache_for("attestation", false)
}

pub fn download_barretenberg_srs_to_cache_for(
    circuit_name: &str,
    recursive: bool,
) -> Result<PathBuf> {
    let path = barretenberg_srs_cache_path_for(circuit_name);
    if path.is_file() && setup_cached_barretenberg_srs_for(circuit_name, recursive).is_ok() {
        return Ok(path);
    }

    let bytecode = load_circuit_bytecode_for(circuit_name)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let subgroup_size = get_subgroup_size(&bytecode, recursive);
    let srs = get_srs(subgroup_size, None);
    let path_string = cached_srs_path_string(circuit_name)?;
    LocalSrs(srs).save(Some(&path_string));

    Ok(path)
}

pub fn setup_cached_barretenberg_srs() -> Result<()> {
    setup_cached_barretenberg_srs_for("attestation", false)
}

pub fn setup_cached_barretenberg_srs_for(circuit_name: &str, recursive: bool) -> Result<()> {
    let bytecode = load_circuit_bytecode_for(circuit_name)?;
    let path = barretenberg_srs_cache_path_for(circuit_name);
    if !path.is_file() {
        return Err(ZkTlsnError::MissingCachedSrs {
            path: path.display().to_string(),
        });
    }

    let path_string = cached_srs_path_string(circuit_name)?;
    match catch_unwind(AssertUnwindSafe(|| {
        setup_srs_from_bytecode(&bytecode, Some(&path_string), recursive)
    })) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(ZkTlsnError::NoirError(error)),
        Err(_) => Err(ZkTlsnError::InvalidCachedSrs {
            path: path.display().to_string(),
        }),
    }
}

pub fn setup_barretenberg_srs() -> Result<()> {
    setup_barretenberg_srs_for("attestation", false)
}

pub fn setup_barretenberg_srs_for(circuit_name: &str, recursive: bool) -> Result<()> {
    let bytecode = load_circuit_bytecode_for(circuit_name)?;
    setup_srs_from_bytecode(&bytecode, None, recursive).map_err(ZkTlsnError::NoirError)?;
    Ok(())
}

fn load_circuit_bytecode_for(circuit_name: &str) -> Result<String> {
    match circuit_name {
        "attestation" => prover::load_circuit_bytecode(),
        "null" => recursive::load_circuit_bytecode_from_target("null"),
        "recursive" => recursive::load_circuit_bytecode_from_target("recursive"),
        name => Err(ZkTlsnError::InvalidInput(format!(
            "unknown circuit name `{name}`"
        ))),
    }
}
