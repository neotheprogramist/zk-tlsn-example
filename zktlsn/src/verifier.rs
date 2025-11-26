use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};

use crate::{
    Proof,
    error::{Result, ZkTlsnError},
    prover::load_circuit_bytecode,
};

pub fn verify_proof(proof: &Proof) -> Result<()> {
    let bytecode = load_circuit_bytecode()?;
    let computed_vk =
        get_ultra_honk_verification_key(&bytecode, false).map_err(ZkTlsnError::NoirError)?;
    if computed_vk != proof.verification_key {
        return Err(ZkTlsnError::VerificationKeyMismatch);
    }
    let is_valid = verify_ultra_honk(proof.proof.clone(), proof.verification_key.clone())
        .map_err(ZkTlsnError::NoirError)?;
    if !is_valid {
        return Err(ZkTlsnError::InvalidProof);
    }
    Ok(())
}
