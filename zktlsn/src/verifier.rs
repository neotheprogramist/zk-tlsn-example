use stwo_circuit::verify_proof as stwo_verify;

use crate::{Proof, error::{Result, ZkTlsnError}};

pub fn verify_proof(proof: Proof) -> Result<()> {
    stwo_verify(proof).map_err(ZkTlsnError::StwoError)
}
