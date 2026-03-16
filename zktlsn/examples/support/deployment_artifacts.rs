#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy::{hex, primitives::Address};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const EMBEDDED_DEPLOYMENT_ARTIFACTS: &str = include_str!("deployment_artifacts.json");
const EMBEDDED_DEPLOYMENT_ARTIFACTS_PATH: &str =
    "zktlsn/examples/support/deployment_artifacts.json";
const VERIFIER_ARTIFACT_PATH: &str = "out/HonkVerifier.sol/HonkVerifier.json";
const VERIFIER_LIBRARY_ARTIFACT_PATH: &str = "out/HonkVerifier.sol/ZKTranscriptLib.json";
const RECURSIVE_VERIFIER_ARTIFACT_PATH: &str =
    "out/RecursiveHonkVerifier.sol/RecursiveHonkVerifier.json";
const RECURSIVE_VERIFIER_LIBRARY_ARTIFACT_PATH: &str =
    "out/RecursiveHonkVerifier.sol/ZKTranscriptLib.json";
const WRAPPER_ARTIFACT_PATH: &str = "out/ZkTlsnVerifier.sol/ZkTlsnVerifier.json";
const STABLE_TOKEN_ARTIFACT_PATH: &str = "out/StableToken.sol/StableToken.json";
const STABLE_MINT_GATE_ARTIFACT_PATH: &str = "out/StableMintGate.sol/StableMintGate.json";
const BATCH_MINT_GATE_ARTIFACT_PATH: &str = "out/BatchMintGate.sol/BatchMintGate.json";
const VERIFIER_LINK_SOURCE: &str = "evm/src/generated/HonkVerifier.sol";
const RECURSIVE_VERIFIER_LINK_SOURCE: &str = "evm/src/generated/RecursiveHonkVerifier.sol";
const VERIFIER_LINK_LIBRARY: &str = "ZKTranscriptLib";
const RECURSIVE_VK_PATH: &str = "target/recursive_keccak/vk";

#[derive(Debug, Clone)]
pub struct PreparedArtifacts {
    pub verification_key: Vec<u8>,
    pub verifier_library_bytecode: Vec<u8>,
    pub verifier_bytecode_template: String,
    pub verifier_link_reference: LinkReference,
    pub stable_token_bytecode: Vec<u8>,
    pub stable_mint_gate_bytecode: Vec<u8>,
    pub wrapper_bytecode: Vec<u8>,
    pub batch: PreparedBatchArtifacts,
}

#[derive(Debug, Clone)]
pub struct PreparedBatchArtifacts {
    pub verification_key: Vec<u8>,
    pub verifier_library_bytecode: Vec<u8>,
    pub verifier_bytecode_template: String,
    pub verifier_link_reference: LinkReference,
    pub batch_mint_gate_bytecode: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LinkReference {
    pub start: usize,
    pub length: usize,
}

#[derive(Debug, Deserialize)]
struct ForgeArtifact {
    bytecode: ForgeBytecode,
}

#[derive(Debug, Deserialize)]
struct ForgeBytecode {
    object: String,
    #[serde(default, rename = "linkReferences")]
    link_references:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<LinkReference>>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DeploymentArtifactsFile {
    verification_key: String,
    verifier_library_bytecode: String,
    verifier_bytecode_template: String,
    verifier_link_reference: LinkReference,
    stable_token_bytecode: String,
    stable_mint_gate_bytecode: String,
    wrapper_bytecode: String,
    batch_verification_key: String,
    batch_verifier_library_bytecode: String,
    batch_verifier_bytecode_template: String,
    batch_verifier_link_reference: LinkReference,
    batch_mint_gate_bytecode: String,
}

pub fn load_embedded_artifacts() -> Result<PreparedArtifacts> {
    serde_json::from_str::<DeploymentArtifactsFile>(EMBEDDED_DEPLOYMENT_ARTIFACTS)
        .context("failed to decode embedded deployment artifacts")?
        .try_into()
}

pub fn write_embedded_artifacts(repo_root: &Path) -> Result<()> {
    let path = repo_root.join(EMBEDDED_DEPLOYMENT_ARTIFACTS_PATH);
    let manifest = build_artifacts_file(repo_root)?;
    let json = serde_json::to_vec_pretty(&manifest)
        .context("failed to encode embedded deployment artifacts")?;

    fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))
}

fn build_artifacts_file(repo_root: &Path) -> Result<DeploymentArtifactsFile> {
    let verifier_artifact = read_artifact(repo_root.join(VERIFIER_ARTIFACT_PATH))?;
    let verifier_library_artifact = read_artifact(repo_root.join(VERIFIER_LIBRARY_ARTIFACT_PATH))?;
    let recursive_verifier_artifact =
        read_artifact(repo_root.join(RECURSIVE_VERIFIER_ARTIFACT_PATH))?;
    let recursive_verifier_library_artifact =
        read_artifact(repo_root.join(RECURSIVE_VERIFIER_LIBRARY_ARTIFACT_PATH))?;
    let wrapper_artifact = read_artifact(repo_root.join(WRAPPER_ARTIFACT_PATH))?;
    let stable_token_artifact = read_artifact(repo_root.join(STABLE_TOKEN_ARTIFACT_PATH))?;
    let stable_mint_gate_artifact = read_artifact(repo_root.join(STABLE_MINT_GATE_ARTIFACT_PATH))?;
    let batch_mint_gate_artifact = read_artifact(repo_root.join(BATCH_MINT_GATE_ARTIFACT_PATH))?;
    let verifier_link_reference = extract_verifier_link_reference(&verifier_artifact)?;
    let recursive_verifier_link_reference = extract_verifier_link_reference_with_source(
        &recursive_verifier_artifact,
        RECURSIVE_VERIFIER_LINK_SOURCE,
    )?;

    ensure!(
        wrapper_artifact.bytecode.link_references.is_empty(),
        "wrapper artifact must not contain link references"
    );
    ensure!(
        stable_token_artifact.bytecode.link_references.is_empty(),
        "stable token artifact must not contain link references"
    );
    ensure!(
        stable_mint_gate_artifact
            .bytecode
            .link_references
            .is_empty(),
        "stable mint gate artifact must not contain link references"
    );
    ensure!(
        batch_mint_gate_artifact.bytecode.link_references.is_empty(),
        "batch mint gate artifact must not contain link references"
    );

    Ok(DeploymentArtifactsFile {
        verification_key: format!(
            "0x{}",
            hex::encode(
                fs::read(repo_root.join("target/vk"))
                    .context("failed to read generated verification key")?
            )
        ),
        verifier_library_bytecode: verifier_library_artifact.bytecode.object,
        verifier_bytecode_template: verifier_artifact.bytecode.object,
        verifier_link_reference,
        stable_token_bytecode: stable_token_artifact.bytecode.object,
        stable_mint_gate_bytecode: stable_mint_gate_artifact.bytecode.object,
        wrapper_bytecode: wrapper_artifact.bytecode.object,
        batch_verification_key: format!(
            "0x{}",
            hex::encode(
                fs::read(repo_root.join(RECURSIVE_VK_PATH))
                    .context("failed to read generated recursive verification key")?
            )
        ),
        batch_verifier_library_bytecode: recursive_verifier_library_artifact.bytecode.object,
        batch_verifier_bytecode_template: recursive_verifier_artifact.bytecode.object,
        batch_verifier_link_reference: recursive_verifier_link_reference,
        batch_mint_gate_bytecode: batch_mint_gate_artifact.bytecode.object,
    })
}

fn read_artifact(path: PathBuf) -> Result<ForgeArtifact> {
    serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to decode {}", path.display()))
}

fn extract_verifier_link_reference(artifact: &ForgeArtifact) -> Result<LinkReference> {
    extract_verifier_link_reference_with_source(artifact, VERIFIER_LINK_SOURCE)
}

fn extract_verifier_link_reference_with_source(
    artifact: &ForgeArtifact,
    link_source: &str,
) -> Result<LinkReference> {
    let source_links = artifact
        .bytecode
        .link_references
        .get(link_source)
        .context("verifier artifact is missing expected link source")?;
    ensure!(
        source_links.len() == 1 && source_links.contains_key(VERIFIER_LINK_LIBRARY),
        "verifier artifact must contain exactly one `{VERIFIER_LINK_LIBRARY}` link reference"
    );

    let reference = source_links
        .get(VERIFIER_LINK_LIBRARY)
        .context("verifier artifact is missing library link references")?
        .first()
        .cloned()
        .context("verifier artifact is missing the library link placeholder")?;
    ensure!(
        reference.length == Address::len_bytes(),
        "verifier link reference must be {} bytes, got {}",
        Address::len_bytes(),
        reference.length
    );
    Ok(reference)
}

impl TryFrom<DeploymentArtifactsFile> for PreparedArtifacts {
    type Error = anyhow::Error;

    fn try_from(file: DeploymentArtifactsFile) -> Result<Self> {
        Ok(Self {
            verification_key: decode_hex(&file.verification_key, "embedded verification key")?,
            verifier_library_bytecode: decode_hex(
                &file.verifier_library_bytecode,
                "embedded verifier library bytecode",
            )?,
            verifier_bytecode_template: file.verifier_bytecode_template,
            verifier_link_reference: file.verifier_link_reference,
            stable_token_bytecode: decode_hex(
                &file.stable_token_bytecode,
                "embedded stable token bytecode",
            )?,
            stable_mint_gate_bytecode: decode_hex(
                &file.stable_mint_gate_bytecode,
                "embedded stable mint gate bytecode",
            )?,
            wrapper_bytecode: decode_hex(&file.wrapper_bytecode, "embedded wrapper bytecode")?,
            batch: PreparedBatchArtifacts {
                verification_key: decode_hex(
                    &file.batch_verification_key,
                    "embedded batch verification key",
                )?,
                verifier_library_bytecode: decode_hex(
                    &file.batch_verifier_library_bytecode,
                    "embedded batch verifier library bytecode",
                )?,
                verifier_bytecode_template: file.batch_verifier_bytecode_template,
                verifier_link_reference: file.batch_verifier_link_reference,
                batch_mint_gate_bytecode: decode_hex(
                    &file.batch_mint_gate_bytecode,
                    "embedded batch mint gate bytecode",
                )?,
            },
        })
    }
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(
        value
            .strip_prefix("0x")
            .with_context(|| format!("{label} must be 0x-prefixed"))?,
    )
    .with_context(|| format!("failed to decode {label}"))
}
