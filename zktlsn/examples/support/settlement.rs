use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use alloy::hex;
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::json;
use zktlsn::{SettlementBundle, validate_generated_solidity_verifier};

use crate::deployment_artifacts;

const GENERATED_VERIFIER_PATH: &str = "evm/src/generated/HonkVerifier.sol";
const FIXTURE_DIR: &str = "evm/testdata";

pub fn prepare_settlement_artifacts(bundle: &SettlementBundle) -> Result<()> {
    let repo_root = repo_root()?;

    write_prover_toml(&repo_root, bundle)?;
    run_command(&repo_root, "nargo", &["compile", "--force"])?;
    run_command(&repo_root.join("circuit"), "nargo", &["execute", "witness"])?;
    run_command(
        &repo_root,
        "bb",
        &[
            "write_vk",
            "-b",
            "./target/circuit.json",
            "-o",
            "./target",
            "--oracle_hash",
            "keccak",
        ],
    )?;
    run_command(
        &repo_root,
        "bb",
        &[
            "prove",
            "-b",
            "./target/circuit.json",
            "-w",
            "./target/witness.gz",
            "-o",
            "./target/solidity",
            "--oracle_hash",
            "keccak",
        ],
    )?;
    run_command(
        &repo_root,
        "bb",
        &[
            "write_solidity_verifier",
            "-k",
            "./target/vk",
            "-o",
            "./target/Verifier.sol",
        ],
    )?;

    verify_cli_artifacts(&repo_root, bundle)?;
    write_fixture_files(&repo_root, bundle)?;
    write_generated_verifier(&repo_root, bundle)?;
    run_command(&repo_root, "forge", &["build"])?;
    deployment_artifacts::write_embedded_artifacts(&repo_root)
        .context("failed to write embedded deployment artifacts")
}

fn repo_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .context("failed to resolve repo root")
}

fn write_prover_toml(repo_root: &Path, bundle: &SettlementBundle) -> Result<()> {
    let path = repo_root.join("circuit/Prover.toml");
    fs::write(path, bundle.noir_inputs.to_prover_toml()).context("failed to write Prover.toml")
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

fn verify_cli_artifacts(repo_root: &Path, bundle: &SettlementBundle) -> Result<()> {
    let keccak = &bundle.keccak_proof;
    let expected_public_inputs = flatten_public_inputs(&keccak.public_inputs);
    let cli_public_inputs = fs::read(repo_root.join("target/solidity/public_inputs"))
        .context("failed to read CLI public inputs")?;
    ensure!(
        cli_public_inputs == expected_public_inputs,
        "CLI public inputs do not match settlement public inputs"
    );

    let cli_proof =
        fs::read(repo_root.join("target/solidity/proof")).context("failed to read CLI proof")?;
    ensure!(
        cli_proof.len() == keccak.solidity_proof.len() && cli_proof.len() % 32 == 0,
        "CLI keccak proof shape does not match settlement proof"
    );

    let cli_vk = fs::read(repo_root.join("target/vk")).context("failed to read CLI vk")?;
    ensure!(
        cli_vk == keccak.verification_key,
        "CLI verification key does not match settlement verification key"
    );
    Ok(())
}

fn write_fixture_files(repo_root: &Path, bundle: &SettlementBundle) -> Result<()> {
    let fixture_dir = repo_root.join(FIXTURE_DIR);
    fs::create_dir_all(&fixture_dir).context("failed to create fixture directory")?;

    let keccak = &bundle.keccak_proof;
    let public_inputs_bin = flatten_public_inputs(&keccak.public_inputs);
    let proof_hex = format!("0x{}", hex::encode(&keccak.solidity_proof));
    let public_inputs_hex = keccak.public_inputs_hex();
    let fixture = json!({
        "attestation": bundle.noir_inputs.attestation,
        "attestation_blinder": bundle.noir_inputs.attestation_blinder,
        "attestation_committed_hash": bundle.noir_inputs.attestation_committed_hash,
        "tx_id": bundle.noir_inputs.tx_id,
        "to_user_id": bundle.noir_inputs.to_user_id,
        "amount": bundle.noir_inputs.amount,
        "mint_amount_wei": u128::from(bundle.noir_inputs.amount)
            .checked_mul(1_000_000_000_000_000_000_u128)
            .context("mint amount overflow")?
            .to_string(),
        "proof_hex": proof_hex,
        "public_inputs": public_inputs_hex,
    });

    [
        (fixture_dir.join("proof.bin"), keccak.solidity_proof.clone()),
        (
            fixture_dir.join("combined_proof.bin"),
            keccak.combined_proof.clone(),
        ),
        (fixture_dir.join("public_inputs.bin"), public_inputs_bin),
        (fixture_dir.join("proof.hex"), proof_hex.into_bytes()),
        (
            fixture_dir.join("public_inputs.json"),
            serde_json::to_vec_pretty(&public_inputs_hex)
                .context("failed to encode public inputs json")?,
        ),
        (
            fixture_dir.join("fixture.json"),
            serde_json::to_vec_pretty(&fixture).context("failed to encode fixture json")?,
        ),
    ]
    .into_iter()
    .try_for_each(|(path, bytes)| {
        fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))
    })
}

fn write_generated_verifier(repo_root: &Path, bundle: &SettlementBundle) -> Result<()> {
    let verifier_source = fs::read_to_string(repo_root.join("target/Verifier.sol"))
        .context("failed to read generated verifier")?;
    validate_generated_solidity_verifier(&verifier_source, bundle.keccak_proof.public_inputs.len())
        .context("generated verifier does not match the expected circuit shape")?;
    let verifier_path = repo_root.join(GENERATED_VERIFIER_PATH);
    let parent = verifier_path
        .parent()
        .ok_or_else(|| anyhow!("generated verifier path is missing parent"))?;
    fs::create_dir_all(parent).context("failed to create generated verifier directory")?;
    fs::write(&verifier_path, verifier_source)
        .with_context(|| format!("failed to write {}", verifier_path.display()))
}

fn flatten_public_inputs(public_inputs: &[[u8; 32]]) -> Vec<u8> {
    public_inputs
        .iter()
        .flat_map(|input| input.iter().copied())
        .collect()
}
