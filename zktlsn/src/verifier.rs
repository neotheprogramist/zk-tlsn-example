use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};

use crate::{
    Proof,
    error::{Result, ZkTlsnError},
    prover::load_circuit_bytecode,
};

pub fn verify_proof(proof: &Proof) -> Result<()> {
    verify_verification_key(&proof.verification_key)?;
    verify_proof_validity(proof)?;

    tracing::info!("Proof verified successfully");
    Ok(())
}

fn verify_verification_key(provided_vk: &[u8]) -> Result<()> {
    let bytecode = load_circuit_bytecode()?;
    let computed_vk =
        get_ultra_honk_verification_key(&bytecode, false).map_err(ZkTlsnError::NoirError)?;

    if computed_vk != provided_vk {
        return Err(ZkTlsnError::VerificationKeyMismatch);
    }

    Ok(())
}

fn verify_proof_validity(proof: &Proof) -> Result<()> {
    let is_valid = verify_ultra_honk(proof.proof.clone(), proof.verification_key.clone())
        .map_err(ZkTlsnError::NoirError)?;

    if !is_valid {
        return Err(ZkTlsnError::InvalidProof);
    }

    tracing::debug!("Proof cryptographic validity confirmed");
    Ok(())
}
