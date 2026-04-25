use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use alloy::{hex, primitives::FixedBytes};
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::json;
use zktlsn_core::zk::{
    KeccakProof, Proof, RECURSIVE_PUBLIC_INPUTS, RecursiveSettlement, aggregate_attestations,
    generate_honk_solidity_verifier, validate_generated_solidity_verifier,
};

use super::chain::{
    connect_anvil, deploy_contracts, load_settlement_artifacts, repo_root,
    write_generated_artifacts, write_local_deployment,
};

const GENERATED_VERIFIER_PATH: &str = ".data/evm/generated/SettlementHonkVerifier.sol";
const FIXTURE_DIR: &str = ".data/evm/testdata";
const KECCAK_DIR: &str = ".data/settlement/keccak";

pub async fn prepare_settlement_artifacts(
    attestation_proofs: &[Proof],
    to_user_id: u64,
    anvil_rpc_url: &str,
    anvil_private_key: &str,
) -> Result<()> {
    let repo_root = repo_root()?;
    let bundle = aggregate_attestations(attestation_proofs, to_user_id)
        .context("failed to build deterministic settlement bundle")?;

    write_generated_verifier(&repo_root, &bundle.keccak_proof)?;
    write_fixture_files(&repo_root, &bundle)?;
    run_command(&repo_root, "forge", &["build"])?;
    write_generated_artifacts(&repo_root)
        .context("failed to write generated deployment artifacts")?;

    let artifacts = load_settlement_artifacts(&repo_root, &bundle.keccak_proof)
        .context("failed to reload settlement deployment artifacts")?;
    let (provider, deployer) = connect_anvil(anvil_rpc_url, anvil_private_key)
        .context("failed to connect to Anvil; start Anvil before running fixture")?;
    let null_vk_hash = FixedBytes::<32>::from(bundle.state.null_vk_hash);
    let recursive_vk_hash = FixedBytes::<32>::from(bundle.state.recursive_vk_hash);
    let inner_vk_hash = FixedBytes::<32>::from(bundle.state.inner_vk_hash);
    let contracts = deploy_contracts(
        &provider,
        deployer,
        &artifacts,
        bundle.state.to_user_id,
        null_vk_hash,
        recursive_vk_hash,
        inner_vk_hash,
    )
    .await
    .context("failed to deploy settlement contracts")?;
    let deployment = write_local_deployment(
        &repo_root,
        &provider,
        deployer,
        contracts,
        bundle.state.to_user_id,
    )
    .await
    .context("failed to persist settlement deployment manifest")?;

    println!(
        "Deployed settlement contracts chain_id={} verifier={} token={} gate={}",
        deployment.chain_id, deployment.verifier, deployment.token, deployment.gate
    );
    Ok(())
}

fn write_generated_verifier(repo_root: &Path, proof: &KeccakProof) -> Result<()> {
    let source = generate_honk_solidity_verifier(&proof.verification_key, "SettlementHonkVerifier")
        .context("failed to generate settlement Solidity verifier")?;
    ensure!(
        source.contains("contract SettlementHonkVerifier is"),
        "generated settlement verifier is missing the expected contract declaration"
    );
    validate_generated_solidity_verifier(&source, RECURSIVE_PUBLIC_INPUTS)
        .context("generated settlement verifier does not match the expected circuit shape")?;

    let verifier_path = repo_root.join(GENERATED_VERIFIER_PATH);
    let parent = verifier_path
        .parent()
        .ok_or_else(|| anyhow!("generated verifier path is missing parent"))?;
    fs::create_dir_all(parent).context("failed to create generated verifier directory")?;
    fs::write(&verifier_path, source)
        .with_context(|| format!("failed to write {}", verifier_path.display()))?;

    let keccak_dir = repo_root.join(KECCAK_DIR);
    fs::create_dir_all(&keccak_dir).context("failed to create settlement keccak directory")?;
    fs::write(keccak_dir.join("vk"), &proof.verification_key)
        .context("failed to write settlement verification key")?;
    Ok(())
}

fn write_fixture_files(repo_root: &Path, bundle: &RecursiveSettlement) -> Result<()> {
    let fixture_dir = repo_root.join(FIXTURE_DIR);
    fs::create_dir_all(&fixture_dir).context("failed to create settlement fixture directory")?;

    let public_inputs_bin = flatten_public_inputs(&bundle.keccak_proof.public_inputs);
    let proof_hex = format!("0x{}", hex::encode(&bundle.keccak_proof.solidity_proof));
    let public_inputs_hex = bundle.keccak_proof.public_inputs_hex();
    let fixture = json!({
        "total_amount": bundle.state.total_amount,
        "transfers_root": format!("0x{}", hex::encode(bundle.state.transfers_root)),
        "to_user_id": bundle.state.to_user_id,
        "null_vk_hash": format!("0x{}", hex::encode(bundle.state.null_vk_hash)),
        "recursive_vk_hash": format!("0x{}", hex::encode(bundle.state.recursive_vk_hash)),
        "inner_vk_hash": format!("0x{}", hex::encode(bundle.state.inner_vk_hash)),
        "proof_hex": proof_hex,
        "public_inputs": public_inputs_hex,
    });
    let public_inputs_json = serde_json::to_vec_pretty(&public_inputs_hex)
        .context("failed to encode settlement public inputs")?;
    let fixture_json =
        serde_json::to_vec_pretty(&fixture).context("failed to encode settlement fixture")?;

    let writes: [(PathBuf, &[u8]); 5] = [
        (
            fixture_dir.join("settlement_proof.bin"),
            &bundle.keccak_proof.solidity_proof,
        ),
        (
            fixture_dir.join("settlement_combined_proof.bin"),
            &bundle.keccak_proof.combined_proof,
        ),
        (
            fixture_dir.join("settlement_public_inputs.bin"),
            &public_inputs_bin,
        ),
        (
            fixture_dir.join("settlement_public_inputs.json"),
            &public_inputs_json,
        ),
        (fixture_dir.join("settlement_fixture.json"), &fixture_json),
    ];
    writes.into_iter().try_for_each(|(path, bytes)| {
        fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))
    })
}

fn flatten_public_inputs(public_inputs: &[[u8; 32]]) -> Vec<u8> {
    public_inputs
        .iter()
        .flat_map(|input| input.iter().copied())
        .collect()
}

fn run_command(cwd: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to start `{program} {}`", args.join(" ")))?;
    ensure!(
        status.success(),
        "command failed: `{program} {}` with status {status}",
        args.join(" ")
    );
    Ok(())
}
