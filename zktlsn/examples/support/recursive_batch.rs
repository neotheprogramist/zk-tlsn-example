use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::Value;
use zktlsn::{
    KeccakProof, NoirProverInputs, RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit, RecursiveProofData,
    RecursiveState, hex_field_words_to_bytes, parse_hex_field_word,
};

#[derive(Debug, Clone)]
pub struct VkMaterial {
    pub vk_hash_field: String,
}

#[derive(Debug, Clone)]
pub struct BatchRecursiveBundle {
    pub keccak_proof: KeccakProof,
    pub state: RecursiveState,
}

pub fn generate_batch_recursive_bundle(
    inputs: &[NoirProverInputs],
) -> Result<BatchRecursiveBundle> {
    ensure!(!inputs.is_empty(), "batch requires at least one transfer");

    let expected_to_user_id = inputs[0].to_user_id;
    ensure!(
        inputs
            .iter()
            .all(|input| input.to_user_id == expected_to_user_id),
        "all batch transfers must target the same to_user_id"
    );

    for circuit in [
        RecursiveCircuit::Attestation,
        RecursiveCircuit::Null,
        RecursiveCircuit::Recursive,
    ] {
        circuit
            .prepare_cached_srs()
            .with_context(|| format!("failed to prepare cached SRS for {}", circuit.name()))?;
    }

    let inner_vk = load_vk_material(RecursiveCircuit::Attestation)
        .context("failed to load inner circuit verification key material")?;
    let null_vk = load_vk_material(RecursiveCircuit::Null)
        .context("failed to load null circuit verification key material")?;
    let recursive_vk = load_vk_material(RecursiveCircuit::Recursive)
        .context("failed to load recursive circuit verification key material")?;

    let mut prev = prove_null_bootstrap(
        expected_to_user_id,
        &null_vk.vk_hash_field,
        &recursive_vk.vk_hash_field,
    )
    .context("failed to prove null bootstrap")?;
    let mut prev_key_hash = null_vk.vk_hash_field.clone();
    let mut final_witness = None;

    for input in inputs {
        let inner = prove_inner_for_recursion(input)
            .with_context(|| format!("failed to prove inner transfer {}", input.tx_id))?;
        let witness = recursive_witness_values(
            &inner,
            &prev,
            &inner_vk.vk_hash_field,
            &prev_key_hash,
            &null_vk.vk_hash_field,
            &recursive_vk.vk_hash_field,
        );
        prev = prove_recursive_step(&witness)
            .with_context(|| format!("failed to aggregate transfer {}", input.tx_id))?;
        prev_key_hash = recursive_vk.vk_hash_field.clone();
        final_witness = Some(witness);
    }

    let final_witness = final_witness.expect("non-empty batch should produce a final witness");
    let keccak_proof = prove_recursive_keccak(&final_witness)
        .context("failed to prove final recursive keccak proof")?;
    let state = state_from_public_inputs(&prev.public_inputs)
        .context("failed to parse final recursive public inputs")?;

    Ok(BatchRecursiveBundle {
        keccak_proof,
        state,
    })
}

pub fn prove_inner_for_recursion(inputs: &NoirProverInputs) -> Result<RecursiveProofData> {
    fs::write(
        RecursiveCircuit::Attestation.prover_toml_path(),
        inputs.to_prover_toml(),
    )
    .context("failed to write inner Prover.toml")?;
    run_nargo_execute_witness(RecursiveCircuit::Attestation)?;
    let mut proof = run_old_api_recursion_inputs(RecursiveCircuit::Attestation)?;
    proof.public_inputs = inputs
        .to_solidity_public_inputs()
        .iter()
        .map(field_word_hex)
        .collect();
    Ok(proof)
}

pub fn prove_null_bootstrap(
    to_user_id: u64,
    allowed_null_vk_hash: &str,
    allowed_recursive_vk_hash: &str,
) -> Result<RecursiveProofData> {
    let prover_toml = format!(
        "to_user_id = \"{to_user_id}\"\nallowed_null_vk_hash = \"{allowed_null_vk_hash}\"\nallowed_recursive_vk_hash = \"{allowed_recursive_vk_hash}\"\n"
    );
    fs::write(RecursiveCircuit::Null.prover_toml_path(), prover_toml)
        .context("failed to write null Prover.toml")?;
    run_nargo_execute_witness(RecursiveCircuit::Null)?;
    let mut proof = run_old_api_recursion_inputs(RecursiveCircuit::Null)?;
    proof.public_inputs = vec![
        zero_field_hex(),
        zero_field_hex(),
        zero_field_hex(),
        u64_to_field_hex(to_user_id),
        allowed_null_vk_hash.to_string(),
        allowed_recursive_vk_hash.to_string(),
    ];
    Ok(proof)
}

pub fn prove_recursive_step(witness_values: &RecursiveWitnessValues) -> Result<RecursiveProofData> {
    fs::write(
        RecursiveCircuit::Recursive.prover_toml_path(),
        recursive_prover_toml(witness_values),
    )
    .context("failed to write recursive Prover.toml")?;
    run_nargo_execute_witness(RecursiveCircuit::Recursive)?;
    run_old_api_recursion_inputs(RecursiveCircuit::Recursive)
}

pub fn recursive_witness_values(
    inner: &RecursiveProofData,
    prev: &RecursiveProofData,
    inner_key_hash: &str,
    prev_key_hash: &str,
    allowed_null_vk_hash: &str,
    allowed_recursive_vk_hash: &str,
) -> RecursiveWitnessValues {
    RecursiveWitnessValues {
        inner_vk: inner.verification_key_fields.clone(),
        inner_proof: inner.proof_fields.clone(),
        inner_public_inputs: inner.public_inputs.clone(),
        inner_key_hash: inner_key_hash.to_string(),
        prev_vk: prev.verification_key_fields.clone(),
        prev_proof: prev.proof_fields.clone(),
        prev_public_inputs: prev.public_inputs.clone(),
        prev_key_hash: prev_key_hash.to_string(),
        allowed_null_vk_hash: allowed_null_vk_hash.to_string(),
        allowed_recursive_vk_hash: allowed_recursive_vk_hash.to_string(),
    }
}

pub fn prove_recursive_keccak(witness_values: &RecursiveWitnessValues) -> Result<KeccakProof> {
    let temp_dir = temp_dir("recursive_keccak")?;
    fs::write(
        RecursiveCircuit::Recursive.prover_toml_path(),
        recursive_prover_toml(witness_values),
    )
    .context("failed to write recursive Prover.toml for keccak proof")?;
    run_nargo_execute_witness(RecursiveCircuit::Recursive)?;
    let witness_path = repo_root().join("target/witness.gz");

    let recursive_srs = RecursiveCircuit::Recursive.srs_cache_path();
    let recursive_srs_dir = recursive_srs
        .parent()
        .ok_or_else(|| anyhow!("SRS cache path has no parent: {}", recursive_srs.display()))?;
    let vk_dir = temp_dir.join("vk");
    fs::create_dir_all(&vk_dir).context("failed to create temporary vk directory")?;
    run_command(
        repo_root(),
        "bb",
        &[
            "-c",
            &recursive_srs_dir.display().to_string(),
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
            &vk_dir.display().to_string(),
        ],
    )
    .context("failed to write recursive keccak verification key")?;

    let proof_dir = temp_dir.join("proof");
    fs::create_dir_all(&proof_dir).context("failed to create temporary proof directory")?;
    run_command(
        repo_root(),
        "bb",
        &[
            "-c",
            &recursive_srs_dir.display().to_string(),
            "prove",
            "-s",
            "ultra_honk",
            "-b",
            &RecursiveCircuit::Recursive
                .bytecode_path()
                .display()
                .to_string(),
            "-w",
            &witness_path.display().to_string(),
            "-k",
            &vk_dir.join("vk").display().to_string(),
            "--oracle_hash",
            "keccak",
            "--output_format",
            "bytes_and_fields",
            "--recursive",
            "-o",
            &proof_dir.display().to_string(),
        ],
    )
    .context("failed to prove recursive keccak proof")?;

    let verification_key = fs::read(vk_dir.join("vk")).context("failed to read recursive vk")?;
    let solidity_proof =
        fs::read(proof_dir.join("proof")).context("failed to read recursive proof bytes")?;
    let public_inputs_bytes = fs::read(proof_dir.join("public_inputs"))
        .context("failed to read recursive public input bytes")?;
    let public_inputs_fields = read_json_string_array(&proof_dir.join("public_inputs_fields.json"))
        .context("failed to read recursive public input fields")?;

    let public_inputs = flatten_field_bytes(&public_inputs_fields)?;
    let combined_proof = public_inputs_bytes
        .iter()
        .copied()
        .chain(solidity_proof.iter().copied())
        .collect();

    Ok(KeccakProof {
        verification_key,
        combined_proof,
        solidity_proof,
        public_inputs,
    })
}

pub fn load_vk_material(circuit: RecursiveCircuit) -> Result<VkMaterial> {
    let output_dir = temp_dir(&format!("{}_vk", circuit.name()))?;
    let srs_path = circuit.srs_cache_path();
    let srs_dir = srs_path
        .parent()
        .ok_or_else(|| anyhow!("SRS cache path has no parent: {}", srs_path.display()))?;
    run_command(
        repo_root(),
        "bb",
        &[
            "-c",
            &srs_dir.display().to_string(),
            "write_vk",
            "-s",
            "ultra_honk",
            "-b",
            &circuit.bytecode_path().display().to_string(),
            "--oracle_hash",
            "poseidon2",
            "--output_format",
            "bytes_and_fields",
            "--recursive",
            "-o",
            &output_dir.display().to_string(),
        ],
    )
    .with_context(|| format!("failed to write vk for {}", circuit.name()))?;

    let vk_hash = fs::read_to_string(output_dir.join("vk_hash_fields.json"))
        .context("failed to read vk hash field")?;
    Ok(VkMaterial {
        vk_hash_field: vk_hash.trim().trim_matches('"').to_string(),
    })
}

pub fn state_from_public_inputs(public_inputs: &[String]) -> Result<RecursiveState> {
    ensure!(
        public_inputs.len() == RECURSIVE_PUBLIC_INPUTS,
        "expected {RECURSIVE_PUBLIC_INPUTS} recursive public inputs, got {}",
        public_inputs.len()
    );
    Ok(RecursiveState {
        total_amount: field_word_to_u64(&public_inputs[1])?,
        transfers_root: parse_hex_field_word(&public_inputs[2])?,
        to_user_id: field_word_to_u64(&public_inputs[3])?,
        allowed_null_vk_hash: parse_hex_field_word(&public_inputs[4])?,
        allowed_recursive_vk_hash: parse_hex_field_word(&public_inputs[5])?,
    })
}

#[derive(Debug, Clone)]
pub struct RecursiveWitnessValues {
    pub inner_vk: Vec<String>,
    pub inner_proof: Vec<String>,
    pub inner_public_inputs: Vec<String>,
    pub inner_key_hash: String,
    pub prev_vk: Vec<String>,
    pub prev_proof: Vec<String>,
    pub prev_public_inputs: Vec<String>,
    pub prev_key_hash: String,
    pub allowed_null_vk_hash: String,
    pub allowed_recursive_vk_hash: String,
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zktlsn crate should live under the workspace root")
}

fn run_nargo_execute_witness(circuit: RecursiveCircuit) -> Result<()> {
    run_command(
        repo_root(),
        "nargo",
        &["execute", "--package", circuit.name(), "witness"],
    )
    .with_context(|| format!("failed to execute witness for {}", circuit.name()))
}

fn run_old_api_recursion_inputs(circuit: RecursiveCircuit) -> Result<RecursiveProofData> {
    let output_dir = temp_dir(circuit.name())?;
    let srs_path = circuit.srs_cache_path();
    let srs_dir = srs_path
        .parent()
        .ok_or_else(|| anyhow!("SRS cache path has no parent: {}", srs_path.display()))?;
    run_command(
        repo_root(),
        "bb",
        &[
            "-c",
            &srs_dir.display().to_string(),
            "OLD_API",
            "write_recursion_inputs_ultra_honk",
            "-b",
            &circuit.bytecode_path().display().to_string(),
            "-o",
            &output_dir.display().to_string(),
        ],
    )
    .with_context(|| format!("failed to write recursion inputs for {}", circuit.name()))?;
    read_recursive_proof_data(&output_dir.join("Prover.toml"))
}

fn read_recursive_proof_data(path: &Path) -> Result<RecursiveProofData> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(RecursiveProofData {
        proof_fields: parse_toml_string_array(&contents, "proof")?,
        public_inputs: parse_toml_string_array(&contents, "public_inputs")?,
        verification_key_fields: parse_toml_string_array(&contents, "verification_key")?,
    })
}

fn recursive_prover_toml(values: &RecursiveWitnessValues) -> String {
    let mut toml = String::new();
    push_hex_array(&mut toml, "inner_vk", &values.inner_vk);
    push_hex_array(&mut toml, "inner_proof", &values.inner_proof);
    push_hex_array(
        &mut toml,
        "inner_public_inputs",
        &values.inner_public_inputs,
    );
    toml.push_str(&format!("inner_key_hash = \"{}\"\n", values.inner_key_hash));
    push_hex_array(&mut toml, "prev_vk", &values.prev_vk);
    push_hex_array(&mut toml, "prev_proof", &values.prev_proof);
    push_hex_array(&mut toml, "prev_public_inputs", &values.prev_public_inputs);
    toml.push_str(&format!("prev_key_hash = \"{}\"\n", values.prev_key_hash));
    toml.push_str(&format!(
        "allowed_null_vk_hash = \"{}\"\nallowed_recursive_vk_hash = \"{}\"\n",
        values.allowed_null_vk_hash, values.allowed_recursive_vk_hash,
    ));
    toml
}

fn push_hex_array(buffer: &mut String, name: &str, values: &[String]) {
    buffer.push_str(name);
    buffer.push_str(" = [");
    if !values.is_empty() {
        buffer.push('\n');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                buffer.push_str(",\n");
            }
            buffer.push_str("  \"");
            buffer.push_str(value);
            buffer.push('"');
        }
        buffer.push('\n');
    }
    buffer.push_str("]\n");
}

fn parse_toml_string_array(contents: &str, key: &str) -> Result<Vec<String>> {
    let needle = format!("{key} = [");
    let start = contents
        .find(&needle)
        .ok_or_else(|| anyhow!("missing `{key}` array"))?;
    let rest = &contents[start + needle.len()..];
    let end = rest
        .find(']')
        .ok_or_else(|| anyhow!("unterminated `{key}` array"))?;
    let body = &rest[..end];
    Ok(body
        .split(',')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.trim_end_matches(',').trim_matches('"').to_string())
        .collect())
}

fn read_json_string_array(path: &Path) -> Result<Vec<String>> {
    let json =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_str(&json)
        .with_context(|| format!("failed to decode {}", path.display()))?;
    value
        .as_array()
        .ok_or_else(|| anyhow!("{} is not a JSON array", path.display()))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{} contains a non-string item", path.display()))
        })
        .collect()
}

fn flatten_field_bytes(fields: &[String]) -> Result<Vec<[u8; 32]>> {
    Ok(hex_field_words_to_bytes(fields)?)
}

fn field_word_hex(word: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for byte in word {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn zero_field_hex() -> String {
    field_word_hex(&[0u8; 32])
}

fn u64_to_field_hex(value: u64) -> String {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    field_word_hex(&word)
}

fn field_word_to_u64(value: &str) -> Result<u64> {
    let bytes = parse_hex_field_word(value)?;
    ensure!(
        bytes[..24].iter().all(|byte| *byte == 0),
        "field `{value}` does not fit in u64"
    );
    Ok(u64::from_be_bytes(
        bytes[24..].try_into().expect("slice length"),
    ))
}

fn temp_dir(label: &str) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("zktlsn_{label}_{timestamp}"));
    fs::create_dir_all(&path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(path)
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
