use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use alloy::hex;
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::json;
use tokio::runtime::Builder;
use zktlsn::{
    RECURSIVE_PUBLIC_INPUTS, SignedTransferTicket, generate_honk_solidity_verifier,
    validate_generated_solidity_verifier,
};

use crate::{
    deployment_artifacts,
    onchain_settlement::{
        DEFAULT_ANVIL_PRIVATE_KEY, DEFAULT_ANVIL_RPC_URL, connect_anvil, deploy_contracts,
        load_settlement_artifacts, repo_root, write_local_deployment,
    },
    recursive_batch,
};

const GENERATED_VERIFIER_PATH: &str = "evm/src/generated/SettlementHonkVerifier.sol";
const FIXTURE_DIR: &str = "evm/testdata";
const KECCAK_DIR: &str = "target/settlement_keccak";

pub fn prepare_settlement_artifacts(tickets: &[SignedTransferTicket]) -> Result<()> {
    let repo_root = repo_root()?;
    let bundle = recursive_batch::generate_settlement_bundle(tickets)
        .context("failed to build deterministic settlement bundle")?;

    write_generated_verifier(&repo_root, &bundle.keccak_proof)?;
    write_fixture_files(&repo_root, tickets, &bundle)?;
    run_command(&repo_root, "forge", &["build"])?;
    deployment_artifacts::write_embedded_artifacts(&repo_root)
        .context("failed to write embedded deployment artifacts")?;

    let artifacts = load_settlement_artifacts(&bundle.keccak_proof)
        .context("failed to reload settlement deployment artifacts")?;
    let rpc_url = anvil_rpc_url();
    let private_key = anvil_private_key();
    let (provider, deployer) = connect_anvil(&rpc_url, &private_key)
        .context("failed to connect to Anvil; start Anvil before running fixture")?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create Tokio runtime for fixture deploy")?;
    let contracts = runtime
        .block_on(deploy_contracts(
            &provider,
            deployer,
            &artifacts,
            bundle.state.to_user_id,
        ))
        .context("failed to deploy settlement contracts")?;
    let deployment = runtime
        .block_on(write_local_deployment(
            &repo_root,
            &provider,
            deployer,
            contracts,
            bundle.state.to_user_id,
        ))
        .context("failed to persist settlement deployment manifest")?;

    println!(
        "Deployed settlement contracts chain_id={} verifier={} token={} gate={}",
        deployment.chain_id, deployment.verifier, deployment.token, deployment.gate
    );
    Ok(())
}

fn write_generated_verifier(repo_root: &Path, proof: &zktlsn::KeccakProof) -> Result<()> {
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

fn write_fixture_files(
    repo_root: &Path,
    tickets: &[SignedTransferTicket],
    bundle: &recursive_batch::SettlementBundle,
) -> Result<()> {
    let fixture_dir = repo_root.join(FIXTURE_DIR);
    fs::create_dir_all(&fixture_dir).context("failed to create settlement fixture directory")?;

    let public_inputs_bin = flatten_public_inputs(&bundle.keccak_proof.public_inputs);
    let proof_hex = format!("0x{}", hex::encode(&bundle.keccak_proof.solidity_proof));
    let public_inputs_hex = bundle.keccak_proof.public_inputs_hex();
    let fixture = json!({
        "tickets": tickets.iter().map(|ticket| json!({
            "tx_id": ticket.tx_id,
            "to_user_id": ticket.to_user_id,
            "amount": ticket.amount,
            "signature": ticket.signature,
        })).collect::<Vec<_>>(),
        "total_amount": bundle.state.total_amount,
        "transfers_root": format!("0x{}", hex::encode(bundle.state.transfers_root)),
        "to_user_id": bundle.state.to_user_id,
        "proof_hex": proof_hex,
        "public_inputs": public_inputs_hex,
    });

    [
        (
            fixture_dir.join("settlement_proof.bin"),
            bundle.keccak_proof.solidity_proof.clone(),
        ),
        (
            fixture_dir.join("settlement_combined_proof.bin"),
            bundle.keccak_proof.combined_proof.clone(),
        ),
        (
            fixture_dir.join("settlement_public_inputs.bin"),
            public_inputs_bin,
        ),
        (
            fixture_dir.join("settlement_public_inputs.json"),
            serde_json::to_vec_pretty(&public_inputs_hex)
                .context("failed to encode settlement public inputs")?,
        ),
        (
            fixture_dir.join("settlement_fixture.json"),
            serde_json::to_vec_pretty(&fixture).context("failed to encode settlement fixture")?,
        ),
    ]
    .into_iter()
    .try_for_each(|(path, bytes): (PathBuf, Vec<u8>)| {
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

fn anvil_rpc_url() -> String {
    env::var("ZKTLSN_ANVIL_RPC_URL").unwrap_or_else(|_| DEFAULT_ANVIL_RPC_URL.to_string())
}

fn anvil_private_key() -> String {
    env::var("ZKTLSN_ANVIL_PRIVATE_KEY").unwrap_or_else(|_| DEFAULT_ANVIL_PRIVATE_KEY.to_string())
}
