mod commitment;
mod error;
mod padding;
mod prover;
mod verifier;

#[cfg(test)]
mod tests;

pub use commitment::{BoundCommitment, bind_commitments_to_keys};
pub use error::{Result, ZkTlsnError};
use noir::barretenberg::srs::setup_srs_from_bytecode;
pub use padding::PaddingConfig;
pub use prover::{Proof, generate_proof};
pub use verifier::verify_proof;

pub fn setup_barretenberg_srs() -> Result<()> {
    let bytecode = prover::load_circuit_bytecode()?;
    setup_srs_from_bytecode(&bytecode, None, false).map_err(ZkTlsnError::NoirError)?;
    Ok(())
}
