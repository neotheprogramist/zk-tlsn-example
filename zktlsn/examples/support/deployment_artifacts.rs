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
const WRAPPER_ARTIFACT_PATH: &str = "out/ZkTlsnVerifier.sol/ZkTlsnVerifier.json";
const VERIFIER_LINK_SOURCE: &str = "evm/src/generated/HonkVerifier.sol";
const VERIFIER_LINK_LIBRARY: &str = "ZKTranscriptLib";

#[derive(Debug, Clone)]
pub struct PreparedArtifacts {
    pub verification_key: Vec<u8>,
    pub verifier_library_bytecode: Vec<u8>,
    pub verifier_bytecode_template: String,
    pub verifier_link_reference: LinkReference,
    pub wrapper_bytecode: Vec<u8>,
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
    wrapper_bytecode: String,
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
    let wrapper_artifact = read_artifact(repo_root.join(WRAPPER_ARTIFACT_PATH))?;
    let verifier_link_reference = extract_verifier_link_reference(&verifier_artifact)?;

    ensure!(
        wrapper_artifact.bytecode.link_references.is_empty(),
        "wrapper artifact must not contain link references"
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
        wrapper_bytecode: wrapper_artifact.bytecode.object,
    })
}

fn read_artifact(path: PathBuf) -> Result<ForgeArtifact> {
    serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to decode {}", path.display()))
}

fn extract_verifier_link_reference(artifact: &ForgeArtifact) -> Result<LinkReference> {
    let source_links = artifact
        .bytecode
        .link_references
        .get(VERIFIER_LINK_SOURCE)
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
            wrapper_bytecode: decode_hex(&file.wrapper_bytecode, "embedded wrapper bytecode")?,
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
