mod commitment;
mod error;
mod padding;
mod proof;
mod prover;
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
pub use verifier::validate_generated_solidity_verifier;

const SRS_CACHE_DIR: &str = "srs_cache";
const CIRCUIT_SRS_FILE: &str = "circuit.srs";

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zktlsn crate should live under the workspace root")
}

fn cached_srs_path_string() -> Result<String> {
    let path = barretenberg_srs_cache_path();
    path.to_str().map(str::to_owned).ok_or_else(|| {
        ZkTlsnError::InvalidInput(format!("invalid UTF-8 SRS path: {}", path.display()))
    })
}

pub fn barretenberg_srs_cache_path() -> PathBuf {
    repo_root().join(SRS_CACHE_DIR).join(CIRCUIT_SRS_FILE)
}

pub fn download_barretenberg_srs_to_cache() -> Result<PathBuf> {
    let path = barretenberg_srs_cache_path();
    if path.is_file() && setup_cached_barretenberg_srs().is_ok() {
        return Ok(path);
    }

    let bytecode = prover::load_circuit_bytecode()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let subgroup_size = get_subgroup_size(&bytecode, false);
    let srs = get_srs(subgroup_size, None);
    let path_string = cached_srs_path_string()?;
    LocalSrs(srs).save(Some(&path_string));

    Ok(path)
}

pub fn setup_cached_barretenberg_srs() -> Result<()> {
    let bytecode = prover::load_circuit_bytecode()?;
    let path = barretenberg_srs_cache_path();
    if !path.is_file() {
        return Err(ZkTlsnError::MissingCachedSrs {
            path: path.display().to_string(),
        });
    }

    let path_string = cached_srs_path_string()?;
    match catch_unwind(AssertUnwindSafe(|| {
        setup_srs_from_bytecode(&bytecode, Some(&path_string), false)
    })) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(ZkTlsnError::NoirError(error)),
        Err(_) => Err(ZkTlsnError::InvalidCachedSrs {
            path: path.display().to_string(),
        }),
    }
}

pub fn setup_barretenberg_srs() -> Result<()> {
    let bytecode = prover::load_circuit_bytecode()?;
    setup_srs_from_bytecode(&bytecode, None, false).map_err(ZkTlsnError::NoirError)?;
    Ok(())
}
