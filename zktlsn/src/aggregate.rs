use crate::cli::cleanup_cli_outputs;
use crate::error::{Result, ZkTlsnError};
use crate::{
    KeccakProof, Proof, RecursiveCircuit, RecursiveState, build_recursive_prover_toml,
    compile_all_packages, derive_circuit_vk, extract_transfer_fields_from_proof,
    prove_keccak_circuit, prove_noir_recursive_circuit, prove_null_circuit,
    state_from_public_inputs,
};
use tracing::info;

#[derive(Debug, Clone)]
pub struct RecursiveSettlement {
    pub keccak_proof: KeccakProof,
    pub state: RecursiveState,
}

pub fn aggregate_attestations(
    attestation_proofs: &[Proof],
    to_user_id: u64,
) -> Result<RecursiveSettlement> {
    if attestation_proofs.is_empty() {
        return Err(ZkTlsnError::InvalidInput {
            context: "attestation_proofs",
            details: String::from("settlement requires at least one attestation proof"),
        });
    }

    let first_proof = attestation_proofs
        .first()
        .expect("non-empty check above guarantees first proof");
    let expected_to_user_id = extract_transfer_fields_from_proof(first_proof)?.to_user_id;
    for (i, proof) in attestation_proofs.iter().enumerate().skip(1) {
        let fields = extract_transfer_fields_from_proof(proof)?;
        if fields.to_user_id != expected_to_user_id {
            return Err(ZkTlsnError::InvalidInput {
                context: "attestation_proofs",
                details: format!(
                    "attestation proof {i} targets to_user_id {}, expected {expected_to_user_id}",
                    fields.to_user_id
                ),
            });
        }
    }

    info!("Compiling all circuit packages...");
    compile_all_packages()?;

    info!("Deriving circuit verification keys...");
    let attestation_vk = derive_circuit_vk(RecursiveCircuit::Attestation)?;
    let null_vk = derive_circuit_vk(RecursiveCircuit::Null)?;
    let recursive_vk = derive_circuit_vk(RecursiveCircuit::Recursive)?;

    info!("Generating null bootstrap proof...");
    let mut prev = prove_null_circuit(
        to_user_id,
        &null_vk.vk_hash,
        &recursive_vk.vk_hash,
        &attestation_vk.vk_hash,
    )?;

    let n = attestation_proofs.len();
    let mut last_toml = String::new();
    for (index, inner) in attestation_proofs.iter().enumerate() {
        info!(i = index + 1, n, "Recursive step");
        last_toml = build_recursive_prover_toml(
            inner,
            &prev,
            &null_vk.vk_hash,
            &recursive_vk.vk_hash,
            &attestation_vk.vk_hash,
        )?;

        prev = prove_noir_recursive_circuit(RecursiveCircuit::Recursive, &last_toml)?;
    }

    info!("Generating EVM-compatible keccak proof...");
    let keccak_proof = prove_keccak_circuit(RecursiveCircuit::Recursive, &last_toml)?;
    let state = state_from_public_inputs(
        &keccak_proof
            .public_inputs_hex()
            .into_iter()
            .collect::<Vec<_>>(),
    )?;

    cleanup_cli_outputs()?;

    Ok(RecursiveSettlement {
        keccak_proof,
        state,
    })
}
