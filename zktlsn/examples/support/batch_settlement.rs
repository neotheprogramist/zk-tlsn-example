use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use alloy::hex;
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::json;
use zktlsn::{
    NoirProverInputs, RecursiveCircuit, validate_generated_solidity_verifier_for_bytecode,
};

use crate::{deployment_artifacts, recursive_batch};

const GENERATED_RECURSIVE_VERIFIER_PATH: &str = "evm/src/generated/RecursiveHonkVerifier.sol";
const RECURSIVE_VERIFIER_OUTPUT_PATH: &str = "target/RecursiveVerifier.sol";
const RECURSIVE_KEY_DIR: &str = "target/recursive_keccak";
const RECURSIVE_CONSTANTS_PATH: &str = "circuits/recursive/src/generated_constants.nr";
const BATCH_FIXTURE_DIR: &str = "evm/testdata";

pub fn prepare_batch_settlement_artifacts(inputs: &[NoirProverInputs]) -> Result<()> {
    let repo_root = repo_root()?;

    run_command(&repo_root, "nargo", &["compile", "--force"])?;
    RecursiveCircuit::Attestation
        .prepare_cached_srs()
        .context("failed to prepare inner recursive SRS")?;

    let inner_seed = recursive_batch::prove_inner_for_recursion(&inputs[0])
        .context("failed to derive recursive inner proof constants")?;
    let inner_vk = recursive_batch::load_vk_material(RecursiveCircuit::Attestation)
        .context("failed to read canonical inner vk hash")?;
    write_recursive_constants(
        &repo_root,
        inner_seed.proof_fields.len(),
        inner_seed.verification_key_fields.len(),
        &inner_vk.vk_hash_field,
    )?;

    run_command(&repo_root, "nargo", &["compile", "--force"])?;

    let bundle = recursive_batch::generate_batch_recursive_bundle(inputs)
        .context("failed to build deterministic recursive batch proof")?;
    write_recursive_verifier(&repo_root)?;
    write_batch_fixture_files(&repo_root, inputs, &bundle)?;

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

fn write_recursive_constants(
    repo_root: &Path,
    proof_fields: usize,
    vk_fields: usize,
    expected_inner_vk_hash: &str,
) -> Result<()> {
    let source = format!(
        "pub global HONK_PROOF_FIELDS: u32 = {proof_fields};\n\
pub global HONK_VK_FIELDS: u32 = {vk_fields};\n\
pub global EXPECTED_INNER_VK_HASH: Field = {expected_inner_vk_hash};\n"
    );
    fs::write(repo_root.join(RECURSIVE_CONSTANTS_PATH), source)
        .context("failed to write recursive generated constants")
}

fn write_recursive_verifier(repo_root: &Path) -> Result<()> {
    let srs_path = RecursiveCircuit::Recursive.srs_cache_path();
    let srs_dir = srs_path
        .parent()
        .ok_or_else(|| anyhow!("SRS cache path has no parent: {}", srs_path.display()))?;
    let recursive_key_dir = repo_root.join(RECURSIVE_KEY_DIR);
    fs::create_dir_all(&recursive_key_dir).context("failed to create recursive key directory")?;

    run_command(
        repo_root,
        "bb",
        &[
            "-c",
            &srs_dir.display().to_string(),
            "write_vk",
            "-s",
            "ultra_honk",
            "-b",
            &RecursiveCircuit::Recursive
                .bytecode_path()
                .display()
                .to_string(),
            "--oracle_hash",
            "keccak",
            "--output_format",
            "bytes",
            "--recursive",
            "-o",
            &recursive_key_dir.display().to_string(),
        ],
    )?;
    run_command(
        repo_root,
        "bb",
        &[
            "write_solidity_verifier",
            "-k",
            &recursive_key_dir.join("vk").display().to_string(),
            "-o",
            RECURSIVE_VERIFIER_OUTPUT_PATH,
        ],
    )?;

    let source = fs::read_to_string(repo_root.join(RECURSIVE_VERIFIER_OUTPUT_PATH))
        .context("failed to read generated recursive verifier")?;
    let source = source.replacen(
        "contract HonkVerifier is",
        "contract RecursiveHonkVerifier is",
        1,
    );
    ensure!(
        source.contains("contract RecursiveHonkVerifier is"),
        "generated recursive verifier is missing the expected contract declaration"
    );
    let recursive_bytecode = fs::read_to_string(RecursiveCircuit::Recursive.bytecode_path())
        .context("failed to read recursive bytecode")?;
    let recursive_program: serde_json::Value =
        serde_json::from_str(&recursive_bytecode).context("failed to decode recursive bytecode")?;
    let bytecode = recursive_program["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("recursive bytecode JSON is missing `bytecode`"))?;
    validate_generated_solidity_verifier_for_bytecode(
        &source,
        bytecode,
        zktlsn::RECURSIVE_PUBLIC_INPUTS,
        true,
    )
    .context("generated recursive verifier does not match the expected circuit shape")?;

    let verifier_path = repo_root.join(GENERATED_RECURSIVE_VERIFIER_PATH);
    let parent = verifier_path
        .parent()
        .ok_or_else(|| anyhow!("recursive verifier path is missing parent"))?;
    fs::create_dir_all(parent).context("failed to create recursive verifier directory")?;
    fs::write(verifier_path, source).context("failed to write generated recursive verifier")
}

fn write_batch_fixture_files(
    repo_root: &Path,
    inputs: &[NoirProverInputs],
    bundle: &recursive_batch::BatchRecursiveBundle,
) -> Result<()> {
    let fixture_dir = repo_root.join(BATCH_FIXTURE_DIR);
    fs::create_dir_all(&fixture_dir).context("failed to create batch fixture directory")?;

    let public_inputs_bin = flatten_public_inputs(&bundle.keccak_proof.public_inputs);
    let proof_hex = format!("0x{}", hex::encode(&bundle.keccak_proof.solidity_proof));
    let public_inputs_hex = bundle.keccak_proof.public_inputs_hex();
    let fixture = json!({
        "transfers": inputs.iter().map(|input| json!({
            "tx_id": input.tx_id,
            "to_user_id": input.to_user_id,
            "amount": input.amount,
            "attestation": input.attestation,
            "attestation_blinder": input.attestation_blinder,
        })).collect::<Vec<_>>(),
        "total_amount": bundle.state.total_amount,
        "transfers_root": format!("0x{}", hex::encode(bundle.state.transfers_root)),
        "to_user_id": bundle.state.to_user_id,
        "null_vk_hash": format!("0x{}", hex::encode(bundle.state.allowed_null_vk_hash)),
        "recursive_vk_hash": format!("0x{}", hex::encode(bundle.state.allowed_recursive_vk_hash)),
        "proof_hex": proof_hex,
        "public_inputs": public_inputs_hex,
    });

    [
        (
            fixture_dir.join("batch_proof.bin"),
            bundle.keccak_proof.solidity_proof.clone(),
        ),
        (
            fixture_dir.join("batch_combined_proof.bin"),
            bundle.keccak_proof.combined_proof.clone(),
        ),
        (
            fixture_dir.join("batch_public_inputs.bin"),
            public_inputs_bin,
        ),
        (
            fixture_dir.join("batch_public_inputs.json"),
            serde_json::to_vec_pretty(&public_inputs_hex)
                .context("failed to encode batch public inputs")?,
        ),
        (
            fixture_dir.join("batch_fixture.json"),
            serde_json::to_vec_pretty(&fixture).context("failed to encode batch fixture json")?,
        ),
    ]
    .into_iter()
    .try_for_each(|(path, bytes)| {
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
