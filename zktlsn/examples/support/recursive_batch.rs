use anyhow::{Context, Result, ensure};
use tracing::info;
use zktlsn::{
    KeccakProof, Proof, RecursiveCircuit, RecursiveState, build_recursive_prover_toml,
    cleanup_cli_outputs, compile_all_packages, derive_circuit_vk, prove_keccak_circuit,
    prove_noir_recursive_circuit, prove_null_circuit, state_from_public_inputs,
};

#[derive(Debug, Clone)]
#[allow(dead_code)] // fields read by settlement.rs / settlement_demo.rs (separate include! contexts)
pub struct SettlementBundle {
    pub keccak_proof: KeccakProof,
    pub state: RecursiveState,
}

pub fn generate_settlement_bundle(
    attestation_proofs: &[Proof],
    to_user_id: u64,
) -> Result<SettlementBundle> {
    ensure!(
        !attestation_proofs.is_empty(),
        "settlement requires at least one attestation proof"
    );

    let _total = attestation_proofs.iter().try_fold(0u64, |total, proof| {
        let fields = zktlsn::extract_transfer_fields_from_proof(proof)
            .context("failed to extract transfer fields from attestation proof")?;
        total
            .checked_add(fields.amount)
            .context("settlement total amount overflow")
    })?;

    let first_proof = attestation_proofs
        .first()
        .context("attestation proofs empty after non-empty check")?;
    let expected_to_user_id = zktlsn::extract_transfer_fields_from_proof(first_proof)
        .context("failed to extract fields from first proof")?
        .to_user_id;
    for (i, proof) in attestation_proofs.iter().enumerate().skip(1) {
        let fields = zktlsn::extract_transfer_fields_from_proof(proof)
            .with_context(|| format!("failed to extract fields from proof {i}"))?;
        ensure!(
            fields.to_user_id == expected_to_user_id,
            "attestation proof {i} targets to_user_id {}, expected {expected_to_user_id}",
            fields.to_user_id
        );
    }

    info!("Compiling all circuit packages...");
    compile_all_packages().context("failed to compile settlement circuits")?;

    info!("Deriving circuit verification keys...");
    let attestation_vk = derive_circuit_vk(RecursiveCircuit::Attestation)
        .context("failed to derive attestation circuit VK")?;
    let null_vk =
        derive_circuit_vk(RecursiveCircuit::Null).context("failed to derive null circuit VK")?;
    let recursive_vk = derive_circuit_vk(RecursiveCircuit::Recursive)
        .context("failed to derive recursive circuit VK")?;

    info!("Generating null bootstrap proof...");
    let mut prev = prove_null_circuit(
        to_user_id,
        &null_vk.vk_hash,
        &recursive_vk.vk_hash,
        &attestation_vk.vk_hash,
    )
    .context("failed to generate null bootstrap proof")?;

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
        )
        .context("failed to build recursive prover TOML")?;

        prev = prove_noir_recursive_circuit(RecursiveCircuit::Recursive, &last_toml)
            .with_context(|| format!("failed to prove recursive step {index}"))?;
    }

    info!("Generating EVM-compatible keccak proof...");
    let keccak_proof = prove_keccak_circuit(RecursiveCircuit::Recursive, &last_toml)
        .context("failed to generate settlement EVM proof")?;
    let state = state_from_public_inputs(
        &keccak_proof
            .public_inputs_hex()
            .into_iter()
            .collect::<Vec<_>>(),
    )
    .context("failed to parse settlement public inputs")?;

    cleanup_cli_outputs().context("failed to clean up CLI output directories")?;

    Ok(SettlementBundle {
        keccak_proof,
        state,
    })
}
