use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    Result, ZkTlsnError,
    recursive::{HONK_FIELD_BYTES, RecursiveCircuit},
    repo_root,
};

const EXPECTED_NARGO_VERSION: &str = "1.0.0-beta.20";
const EXPECTED_BB_VERSION: &str = "5.0.0-nightly.20260324";
const TARGET_DIR: &str = "target";
const CLI_DIR: &str = "cli";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifierTarget {
    Evm,
    NoirRecursive,
}

impl VerifierTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::NoirRecursive => "noir-recursive",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BbProofArtifacts {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; HONK_FIELD_BYTES]>,
    pub verification_key: Vec<u8>,
    pub vk_hash: [u8; HONK_FIELD_BYTES],
}

pub(crate) fn ensure_cli_toolchain() -> Result<()> {
    ensure_command_version("nargo", &["--version"], EXPECTED_NARGO_VERSION)?;
    ensure_command_version("bb", &["--version"], EXPECTED_BB_VERSION)?;
    Ok(())
}

static COMPILED_PACKAGES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

pub(crate) fn compile_package(package: &str) -> Result<()> {
    let set = COMPILED_PACKAGES.get_or_init(|| Mutex::new(HashSet::new()));
    // PROOF: poisoning means a prior holder panicked — unrecoverable state.
    let mut guard = set.lock().expect("COMPILED_PACKAGES mutex poisoned");
    if !guard.insert(package.to_string()) {
        return Ok(());
    }
    drop(guard);
    ensure_cli_toolchain()?;
    run_command(
        repo_root(),
        "nargo",
        &["compile", "--force", "--package", package],
    )?;
    Ok(())
}

pub(crate) fn write_package_prover_toml(package: &str, contents: &str) -> Result<PathBuf> {
    let path = repo_root()
        .join("circuits")
        .join(package)
        .join("Prover.toml");
    fs::write(&path, contents)?;
    Ok(path)
}

pub(crate) fn execute_package(package: &str) -> Result<PathBuf> {
    ensure_cli_toolchain()?;
    let witness_name = next_cli_id(package);
    run_command(
        repo_root(),
        "nargo",
        &["execute", &witness_name, "--package", package],
    )?;
    Ok(repo_root()
        .join(TARGET_DIR)
        .join(format!("{witness_name}.gz")))
}

pub(crate) fn prove_circuit(
    circuit: RecursiveCircuit,
    witness_path: &Path,
    target: VerifierTarget,
) -> Result<BbProofArtifacts> {
    ensure_cli_toolchain()?;
    let output_dir = cli_output_dir(&format!("{}-prove-{}", circuit.name(), target.as_str()));
    fs::create_dir_all(&output_dir)?;
    fs::create_dir_all(crs_path())?;
    let bytecode_path = repo_root()
        .join(TARGET_DIR)
        .join(format!("{}.json", circuit.name()));

    let bytecode_path = path_arg(&bytecode_path)?;
    let witness_path = path_arg(witness_path)?;
    let output_path = path_arg(&output_dir)?;
    run_command(
        repo_root(),
        "bb",
        &[
            "prove",
            "-b",
            &bytecode_path,
            "-w",
            &witness_path,
            "-o",
            &output_path,
            "-t",
            target.as_str(),
            "-s",
            scheme_for(circuit),
            "-c",
            &path_arg(&crs_path())?,
            "--write_vk",
            "--verify",
        ],
    )?;

    Ok(BbProofArtifacts {
        proof: fs::read(output_dir.join("proof"))?,
        public_inputs: read_field_words(&output_dir.join("public_inputs"))?,
        verification_key: fs::read(output_dir.join("vk"))?,
        vk_hash: read_single_field_word(&output_dir.join("vk_hash"))?,
    })
}

pub(crate) fn verify_proof(
    proof: &[u8],
    public_inputs: &[[u8; HONK_FIELD_BYTES]],
    verification_key: &[u8],
    target: VerifierTarget,
) -> Result<()> {
    ensure_cli_toolchain()?;
    let output_dir = cli_output_dir(&format!("verify-{}", target.as_str()));
    fs::create_dir_all(&output_dir)?;

    let proof_path = output_dir.join("proof");
    let public_inputs_path = output_dir.join("public_inputs");
    let vk_path = output_dir.join("vk");
    fs::write(&proof_path, proof)?;
    fs::write(&vk_path, verification_key)?;
    fs::write(&public_inputs_path, flatten_public_inputs(public_inputs))?;

    run_command(
        repo_root(),
        "bb",
        &[
            "verify",
            "-p",
            &path_arg(&proof_path)?,
            "-i",
            &path_arg(&public_inputs_path)?,
            "-k",
            &path_arg(&vk_path)?,
            "-t",
            target.as_str(),
        ],
    )?;
    Ok(())
}

pub(crate) fn write_solidity_verifier(
    vk_path: &Path,
    output_path: &Path,
    target: VerifierTarget,
) -> Result<()> {
    ensure_cli_toolchain()?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // bb 5.0: --optimized is not available for ZK verifiers; emit the
    // non-optimized ZK Solidity verifier instead.
    run_command(
        repo_root(),
        "bb",
        &[
            "write_solidity_verifier",
            "-k",
            &path_arg(vk_path)?,
            "-o",
            &path_arg(output_path)?,
            "-t",
            target.as_str(),
        ],
    )?;
    Ok(())
}

pub(crate) fn write_vk_for_circuit(
    circuit: RecursiveCircuit,
    target: VerifierTarget,
) -> Result<(Vec<u8>, [u8; HONK_FIELD_BYTES])> {
    ensure_cli_toolchain()?;
    let output_dir = cli_output_dir(&format!("{}-write-vk-{}", circuit.name(), target.as_str()));
    fs::create_dir_all(&output_dir)?;
    fs::create_dir_all(crs_path())?;
    let bytecode_path = repo_root()
        .join(TARGET_DIR)
        .join(format!("{}.json", circuit.name()));

    run_command(
        repo_root(),
        "bb",
        &[
            "write_vk",
            "-b",
            &path_arg(&bytecode_path)?,
            "-o",
            &path_arg(&output_dir)?,
            "-t",
            target.as_str(),
            "-s",
            scheme_for(circuit),
            "-c",
            &path_arg(&crs_path())?,
        ],
    )?;

    Ok((
        fs::read(output_dir.join("vk"))?,
        read_single_field_word(&output_dir.join("vk_hash"))?,
    ))
}

pub(crate) fn read_single_field_word(path: &Path) -> Result<[u8; HONK_FIELD_BYTES]> {
    let bytes = fs::read(path)?;
    if bytes.len() != HONK_FIELD_BYTES {
        return Err(ZkTlsnError::InvalidInput {
            context: "single field word",
            details: format!(
                "expected {} bytes in `{}`, got {}",
                HONK_FIELD_BYTES,
                path.display(),
                bytes.len()
            ),
        });
    }
    let mut word = [0u8; HONK_FIELD_BYTES];
    word.copy_from_slice(&bytes);
    Ok(word)
}

pub(crate) fn flatten_public_inputs(public_inputs: &[[u8; HONK_FIELD_BYTES]]) -> Vec<u8> {
    public_inputs
        .iter()
        .flat_map(|input| input.iter().copied())
        .collect()
}

pub(crate) fn read_field_words(path: &Path) -> Result<Vec<[u8; HONK_FIELD_BYTES]>> {
    let bytes = fs::read(path)?;
    read_field_words_from_bytes(&bytes, &path.display().to_string())
}

pub(crate) fn read_field_words_from_bytes(
    bytes: &[u8],
    label: &str,
) -> Result<Vec<[u8; HONK_FIELD_BYTES]>> {
    if !bytes.len().is_multiple_of(HONK_FIELD_BYTES) {
        return Err(ZkTlsnError::InvalidInput {
            context: "field word stream",
            details: format!(
                "`{label}` must contain {}-byte words, got {} bytes",
                HONK_FIELD_BYTES,
                bytes.len()
            ),
        });
    }

    bytes
        .chunks_exact(HONK_FIELD_BYTES)
        .map(|chunk| {
            let mut word = [0u8; HONK_FIELD_BYTES];
            word.copy_from_slice(chunk);
            Ok(word)
        })
        .collect()
}

fn ensure_command_version(program: &str, args: &[&str], expected: &str) -> Result<()> {
    let output = match Command::new(program)
        .args(args)
        .current_dir(repo_root())
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ZkTlsnError::MissingTool {
                tool: program.to_string(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !output.status.success() {
        return Err(ZkTlsnError::CommandFailed {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains(expected) {
        return Err(ZkTlsnError::UnsupportedToolVersion {
            tool: program.to_string(),
            expected: expected.to_string(),
            actual: stdout.trim().to_string(),
        });
    }
    Ok(())
}

fn run_command(cwd: &Path, program: &str, args: &[&str]) -> Result<()> {
    let output = match Command::new(program).args(args).current_dir(cwd).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ZkTlsnError::MissingTool {
                tool: program.to_string(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    if output.status.success() {
        return Ok(());
    }

    Err(ZkTlsnError::CommandFailed {
        program: program.to_string(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

static CLI_OUTPUT_DIRS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();

fn cli_output_dir(label: &str) -> PathBuf {
    let dir = repo_root()
        .join(TARGET_DIR)
        .join(CLI_DIR)
        .join(next_cli_id(label));
    let tracker = CLI_OUTPUT_DIRS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut dirs) = tracker.lock() {
        dirs.push(dir.clone());
    }
    dir
}

pub(crate) fn cleanup_cli_outputs() -> Result<()> {
    let tracker = CLI_OUTPUT_DIRS.get_or_init(|| Mutex::new(Vec::new()));
    // PROOF: poisoning means a prior holder panicked — unrecoverable state.
    let dirs = tracker
        .lock()
        .expect("CLI_OUTPUT_DIRS mutex poisoned")
        .drain(..)
        .collect::<Vec<_>>();
    for dir in dirs {
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
    }
    Ok(())
}

fn crs_path() -> PathBuf {
    repo_root().join(TARGET_DIR).join("crs")
}

fn next_cli_id(label: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{label}-{id}")
}

fn scheme_for(circuit: RecursiveCircuit) -> &'static str {
    match circuit {
        RecursiveCircuit::Attestation | RecursiveCircuit::Null | RecursiveCircuit::Recursive => {
            "ultra_honk"
        }
    }
}

fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| ZkTlsnError::InvalidInput {
            context: "path utf8",
            details: format!("invalid UTF-8 path: {}", path.display()),
        })
}
