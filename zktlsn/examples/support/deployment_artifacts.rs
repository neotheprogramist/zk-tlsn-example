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
const SETTLEMENT_VERIFIER_ARTIFACT_PATH: &str =
    "out/SettlementHonkVerifier.sol/SettlementHonkVerifier.json";
const SETTLEMENT_VERIFIER_LIBRARY_ARTIFACT_PATH: &str =
    "out/SettlementHonkVerifier.sol/ZKTranscriptLib.json";
const STABLE_TOKEN_ARTIFACT_PATH: &str = "out/StableToken.sol/StableToken.json";
const SETTLEMENT_MINT_GATE_ARTIFACT_PATH: &str =
    "out/SettlementMintGate.sol/SettlementMintGate.json";
const SETTLEMENT_VERIFIER_LINK_SOURCE: &str = "evm/src/generated/SettlementHonkVerifier.sol";
const VERIFIER_LINK_LIBRARY: &str = "ZKTranscriptLib";
const SETTLEMENT_VK_PATH: &str = "target/settlement_keccak/vk";
const LOCAL_SETTLEMENT_DEPLOYMENT_PATH: &str = "target/settlement_deployment.json";

#[derive(Debug, Clone)]
pub struct PreparedArtifacts {
    pub stable_token_bytecode: Vec<u8>,
    pub settlement: PreparedSettlementArtifacts,
}

#[derive(Debug, Clone)]
pub struct PreparedSettlementArtifacts {
    pub verification_key: Vec<u8>,
    pub verifier_library_bytecode: Vec<u8>,
    pub verifier_bytecode_template: String,
    pub verifier_link_reference: LinkReference,
    pub settlement_mint_gate_bytecode: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LinkReference {
    pub start: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettlementDeployment {
    pub chain_id: u64,
    pub deployer: Address,
    pub verifier: Address,
    pub token: Address,
    pub gate: Address,
    pub expected_to_user_id: u64,
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
    stable_token_bytecode: String,
    settlement_verification_key: String,
    settlement_verifier_library_bytecode: String,
    settlement_verifier_bytecode_template: String,
    settlement_verifier_link_reference: LinkReference,
    settlement_mint_gate_bytecode: String,
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

pub fn load_local_settlement_deployment(repo_root: &Path) -> Result<Option<SettlementDeployment>> {
    let path = repo_root.join(LOCAL_SETTLEMENT_DEPLOYMENT_PATH);
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&path).with_context(|| {
        format!(
            "failed to read local settlement deployment {}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes)
        .with_context(|| {
            format!(
                "failed to decode local settlement deployment {}",
                path.display()
            )
        })
        .map(Some)
}

pub fn write_local_settlement_deployment(
    repo_root: &Path,
    deployment: &SettlementDeployment,
) -> Result<()> {
    let path = repo_root.join(LOCAL_SETTLEMENT_DEPLOYMENT_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let json = serde_json::to_vec_pretty(deployment)
        .context("failed to encode local settlement deployment")?;
    fs::write(&path, json).with_context(|| {
        format!(
            "failed to write local settlement deployment {}",
            path.display()
        )
    })
}

fn build_artifacts_file(repo_root: &Path) -> Result<DeploymentArtifactsFile> {
    let settlement_verifier_artifact =
        read_artifact(repo_root.join(SETTLEMENT_VERIFIER_ARTIFACT_PATH))?;
    let settlement_verifier_library_artifact =
        read_artifact(repo_root.join(SETTLEMENT_VERIFIER_LIBRARY_ARTIFACT_PATH))?;
    let stable_token_artifact = read_artifact(repo_root.join(STABLE_TOKEN_ARTIFACT_PATH))?;
    let settlement_mint_gate_artifact =
        read_artifact(repo_root.join(SETTLEMENT_MINT_GATE_ARTIFACT_PATH))?;
    let verifier_link_reference = extract_verifier_link_reference(
        &settlement_verifier_artifact,
        SETTLEMENT_VERIFIER_LINK_SOURCE,
    )?;

    ensure!(
        stable_token_artifact.bytecode.link_references.is_empty(),
        "stable token artifact must not contain link references"
    );
    ensure!(
        settlement_mint_gate_artifact
            .bytecode
            .link_references
            .is_empty(),
        "settlement mint gate artifact must not contain link references"
    );

    Ok(DeploymentArtifactsFile {
        stable_token_bytecode: stable_token_artifact.bytecode.object,
        settlement_verification_key: format!(
            "0x{}",
            hex::encode(
                fs::read(repo_root.join(SETTLEMENT_VK_PATH))
                    .context("failed to read generated settlement verification key")?
            )
        ),
        settlement_verifier_library_bytecode: settlement_verifier_library_artifact.bytecode.object,
        settlement_verifier_bytecode_template: settlement_verifier_artifact.bytecode.object,
        settlement_verifier_link_reference: verifier_link_reference,
        settlement_mint_gate_bytecode: settlement_mint_gate_artifact.bytecode.object,
    })
}

fn read_artifact(path: PathBuf) -> Result<ForgeArtifact> {
    serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to decode {}", path.display()))
}

fn extract_verifier_link_reference(
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
            stable_token_bytecode: decode_hex(
                &file.stable_token_bytecode,
                "embedded stable token bytecode",
            )?,
            settlement: PreparedSettlementArtifacts {
                verification_key: decode_hex(
                    &file.settlement_verification_key,
                    "embedded settlement verification key",
                )?,
                verifier_library_bytecode: decode_hex(
                    &file.settlement_verifier_library_bytecode,
                    "embedded settlement verifier library bytecode",
                )?,
                verifier_bytecode_template: file.settlement_verifier_bytecode_template,
                verifier_link_reference: file.settlement_verifier_link_reference,
                settlement_mint_gate_bytecode: decode_hex(
                    &file.settlement_mint_gate_bytecode,
                    "embedded settlement mint gate bytecode",
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
