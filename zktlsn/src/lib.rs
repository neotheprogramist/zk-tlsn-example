mod commitment;
mod error;
mod padding;
mod proof;
mod prover;
mod verifier;

#[cfg(test)]
mod tests;

pub use commitment::{BoundCommitment, bind_commitments_to_keys};
pub use error::{Result, ZkTlsnError};
use noir::barretenberg::srs::setup_srs_from_bytecode;
pub use padding::PaddingConfig;
pub use proof::{extract_committed_hash_from_proof, verify_proof, verify_proof_against_hash};
pub use prover::{
    KeccakProof, NoirProverInputs, Proof, SettlementBundle, derive_noir_prover_inputs,
    generate_settlement_bundle, generate_settlement_bundle_from_inputs,
};
pub use verifier::{
    SolidityVerifierConfig, expected_solidity_verifier_config,
    normalize_generated_solidity_verifier,
};

pub fn setup_barretenberg_srs() -> Result<()> {
    let bytecode = prover::load_circuit_bytecode()?;
    setup_srs_from_bytecode(&bytecode, None, false).map_err(ZkTlsnError::NoirError)?;
    Ok(())
}
