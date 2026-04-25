use std::{
    fs,
    future::IntoFuture,
    path::{Path, PathBuf},
};

use alloy::{
    hex,
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder},
    primitives::{Address, FixedBytes, TxHash, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::{SolCall, SolConstructor, SolError};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const GENERATED_ARTIFACTS_PATH: &str = ".data/e2e/artifacts.json";
const SETTLEMENT_VERIFIER_ARTIFACT_PATH: &str =
    "out/SettlementHonkVerifier.sol/SettlementHonkVerifier.json";
const SETTLEMENT_VERIFIER_LIBRARY_ARTIFACT_PATH: &str =
    "out/SettlementHonkVerifier.sol/ZKTranscriptLib.json";
const STABLE_TOKEN_ARTIFACT_PATH: &str = "out/StableToken.sol/StableToken.json";
const SETTLEMENT_MINT_GATE_ARTIFACT_PATH: &str =
    "out/SettlementMintGate.sol/SettlementMintGate.json";
const SETTLEMENT_VERIFIER_LINK_SOURCE: &str = ".data/evm/generated/SettlementHonkVerifier.sol";
const VERIFIER_LINK_LIBRARY: &str = "ZKTranscriptLib";
const SETTLEMENT_VK_PATH: &str = ".data/settlement/keccak/vk";
const LOCAL_SETTLEMENT_DEPLOYMENT_PATH: &str = ".data/settlement/deployment.json";

sol! {
    contract StableToken {
        constructor(address initialOwner);
        function transferOwnership(address newOwner) external;
        function owner() external view returns (address owner);
        function balanceOf(address account) external view returns (uint256 balance);
    }

    contract SettlementMintGate {
        constructor(
            address verifier_,
            address token_,
            uint256 expectedToUserId_,
            bytes32 expectedNullVkHash_,
            bytes32 expectedRecursiveVkHash_,
            bytes32 expectedInnerVkHash_
        );
        function settle(bytes calldata proof, bytes32[] calldata publicInputs, address recipient) external;
        function claimedRoot(bytes32 transfersRoot) external view returns (bool claimed);
        function EXPECTED_NULL_VK_HASH() external view returns (bytes32);
        function EXPECTED_RECURSIVE_VK_HASH() external view returns (bytes32);
        function EXPECTED_INNER_VK_HASH() external view returns (bytes32);

        error InvalidProof();
        error WrongFiatDestination(uint256 expectedToUserId, uint256 actualToUserId);
        error RootAlreadyClaimed(bytes32 transfersRoot);
        error InvalidVkHashes(
            bytes32 expectedNullVkHash,
            bytes32 actualNullVkHash,
            bytes32 expectedRecursiveVkHash,
            bytes32 actualRecursiveVkHash,
            bytes32 expectedInnerVkHash,
            bytes32 actualInnerVkHash
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OnchainContracts {
    pub verifier: Address,
    pub token: Address,
    pub gate: Address,
}

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

pub fn repo_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .context("failed to resolve repo root")
}

pub fn connect_anvil(rpc_url: &str, private_key: &str) -> Result<(impl Provider, Address)> {
    let signer: PrivateKeySigner = private_key
        .parse()
        .context("failed to parse deployer private key")?;
    let deployer = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().context("failed to parse Anvil RPC URL")?);
    Ok((provider, deployer))
}

pub fn load_settlement_artifacts(
    repo_root: &Path,
    proof: &zktlsn_core::zk::KeccakProof,
) -> Result<PreparedArtifacts> {
    let artifacts = load_generated_artifacts(repo_root)?;
    ensure!(
        artifacts.settlement.verification_key == proof.verification_key,
        "generated settlement artifacts do not match the generated settlement verification key"
    );
    Ok(artifacts)
}

pub async fn deploy_contracts<P>(
    provider: &P,
    deployer: Address,
    artifacts: &PreparedArtifacts,
    expected_to_user_id: u64,
    null_vk_hash: FixedBytes<32>,
    recursive_vk_hash: FixedBytes<32>,
    inner_vk_hash: FixedBytes<32>,
) -> Result<OnchainContracts>
where
    P: Provider,
{
    let library = deploy_bytecode(
        provider,
        artifacts.settlement.verifier_library_bytecode.clone(),
        "settlement verifier library",
    )
    .await?;
    let verifier_bytecode = link_verifier_bytecode(
        &artifacts.settlement.verifier_bytecode_template,
        &artifacts.settlement.verifier_link_reference,
        library,
    )
    .context("failed to link settlement verifier bytecode")?;
    let verifier = deploy_bytecode(provider, verifier_bytecode, "settlement verifier").await?;

    let token_constructor = StableToken::constructorCall {
        initialOwner: deployer,
    };
    let token = deploy_bytecode(
        provider,
        append_constructor_args(
            &artifacts.stable_token_bytecode,
            token_constructor.abi_encode(),
        ),
        "stable token",
    )
    .await?;

    let gate_constructor = SettlementMintGate::constructorCall {
        verifier_: verifier,
        token_: token,
        expectedToUserId_: U256::from(expected_to_user_id),
        expectedNullVkHash_: null_vk_hash,
        expectedRecursiveVkHash_: recursive_vk_hash,
        expectedInnerVkHash_: inner_vk_hash,
    };
    let gate = deploy_bytecode(
        provider,
        append_constructor_args(
            &artifacts.settlement.settlement_mint_gate_bytecode,
            gate_constructor.abi_encode(),
        ),
        "settlement mint gate",
    )
    .await?;

    transfer_token_ownership(provider, deployer, token, gate)
        .await
        .context("failed to transfer token ownership to settlement gate")?;
    ensure!(
        read_token_owner(provider, token)
            .await
            .context("failed to read token owner")?
            == gate,
        "stable token owner was not updated to the settlement gate contract"
    );

    Ok(OnchainContracts {
        verifier,
        token,
        gate,
    })
}

pub async fn write_local_deployment<P>(
    repo_root: &Path,
    provider: &P,
    deployer: Address,
    contracts: OnchainContracts,
    expected_to_user_id: u64,
) -> Result<SettlementDeployment>
where
    P: Provider,
{
    let deployment = SettlementDeployment {
        chain_id: provider
            .get_chain_id()
            .await
            .context("failed to read chain id")?,
        deployer,
        verifier: contracts.verifier,
        token: contracts.token,
        gate: contracts.gate,
        expected_to_user_id,
    };
    write_local_settlement_deployment(repo_root, &deployment)
        .context("failed to write local settlement deployment manifest")?;
    Ok(deployment)
}

pub async fn load_local_deployment<P>(
    repo_root: &Path,
    provider: &P,
    expected_to_user_id: u64,
) -> Result<OnchainContracts>
where
    P: Provider,
{
    let deployment = load_local_settlement_deployment(repo_root)?
        .context("missing local settlement deployment manifest; run `cargo run --bin zktlsn -- fixture` against this Anvil first")?;
    let chain_id = provider
        .get_chain_id()
        .await
        .context("failed to read chain id")?;
    ensure!(
        deployment.chain_id == chain_id,
        "local settlement deployment manifest targets chain id {}, current chain id is {}; rerun `cargo run --bin zktlsn -- fixture`",
        deployment.chain_id,
        chain_id
    );
    ensure!(
        deployment.expected_to_user_id == expected_to_user_id,
        "local settlement deployment expected to_user_id {}, but current server special user id is {}; rerun `cargo run --bin zktlsn -- fixture`",
        deployment.expected_to_user_id,
        expected_to_user_id
    );

    ensure_contract_code(provider, deployment.verifier, "settlement verifier").await?;
    ensure_contract_code(provider, deployment.token, "stable token").await?;
    ensure_contract_code(provider, deployment.gate, "settlement mint gate").await?;

    Ok(OnchainContracts {
        verifier: deployment.verifier,
        token: deployment.token,
        gate: deployment.gate,
    })
}

pub async fn submit_proof_onchain<P>(
    provider: &P,
    deployer: Address,
    gate: Address,
    proof: &zktlsn_core::zk::KeccakProof,
    recipient: Address,
) -> Result<TxHash>
where
    P: Provider,
{
    let public_inputs = proof
        .public_inputs
        .iter()
        .copied()
        .map(FixedBytes::<32>::from)
        .collect::<Vec<_>>();
    let call = SettlementMintGate::settleCall {
        proof: proof.solidity_proof.clone().into(),
        publicInputs: public_inputs,
        recipient,
    };
    let pending = provider
        .send_transaction(
            TransactionRequest::default()
                .with_from(deployer)
                .with_to(gate)
                .with_input(call.abi_encode()),
        )
        .await
        .context("failed to submit settlement transaction")?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .context("failed to fetch settlement receipt")?;
    if !receipt.status() {
        let revert_data = provider
            .call(
                TransactionRequest::default()
                    .with_from(deployer)
                    .with_to(gate)
                    .with_input(call.abi_encode()),
            )
            .await
            .err()
            .map(|e| e.to_string());
        let decoded = revert_data.as_deref().map_or_else(
            || format!("unknown revert (tx: {tx_hash})"),
            decode_settlement_revert,
        );
        anyhow::bail!("settlement transaction reverted: {decoded}");
    }
    Ok(tx_hash)
}

pub async fn read_claimed_root<P>(provider: &P, gate: Address, root: [u8; 32]) -> Result<bool>
where
    P: Provider,
{
    let response = provider
        .call(
            TransactionRequest::default().with_to(gate).with_input(
                SettlementMintGate::claimedRootCall {
                    transfersRoot: FixedBytes::<32>::from(root),
                }
                .abi_encode(),
            ),
        )
        .decode_resp::<SettlementMintGate::claimedRootCall>()
        .into_future()
        .await
        .context("claimedRoot call failed")?;
    response.context("failed to decode claimedRoot response")
}

pub async fn read_token_balance<P>(provider: &P, token: Address, account: Address) -> Result<U256>
where
    P: Provider,
{
    let response = provider
        .call(
            TransactionRequest::default()
                .with_to(token)
                .with_input(StableToken::balanceOfCall { account }.abi_encode()),
        )
        .decode_resp::<StableToken::balanceOfCall>()
        .into_future()
        .await
        .context("balanceOf call failed")?;
    response.context("failed to decode balanceOf response")
}

pub fn mint_amount(amount: u64) -> U256 {
    U256::from(amount) * U256::from(1_000_000_000_000_000_000_u128)
}

fn decode_settlement_revert(error_str: &str) -> String {
    if let Some(hex_start) = error_str.find("0x") {
        let hex_data = &error_str[hex_start..];
        let hex_end = hex_data
            .find(|c: char| !c.is_ascii_hexdigit() && c != 'x')
            .unwrap_or(hex_data.len());
        let hex_slice = &hex_data[..hex_end];

        if let Ok(bytes) = hex::decode(hex_slice.strip_prefix("0x").unwrap_or(hex_slice))
            && let Some(decoded) = try_decode_settlement_error(&bytes)
        {
            return decoded;
        }
    }
    error_str.to_string()
}

fn try_decode_settlement_error(bytes: &[u8]) -> Option<String> {
    let selector: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let data = &bytes[4..];

    if selector == SettlementMintGate::InvalidProof::SELECTOR {
        return Some("InvalidProof: verifier rejected the proof".to_string());
    }
    if selector == SettlementMintGate::WrongFiatDestination::SELECTOR
        && let Ok(e) = <SettlementMintGate::WrongFiatDestination as SolError>::abi_decode_raw(data)
    {
        return Some(format!(
            "WrongFiatDestination: expected to_user_id {}, got {}",
            e.expectedToUserId, e.actualToUserId
        ));
    }
    if selector == SettlementMintGate::RootAlreadyClaimed::SELECTOR
        && let Ok(e) = <SettlementMintGate::RootAlreadyClaimed as SolError>::abi_decode_raw(data)
    {
        return Some(format!(
            "RootAlreadyClaimed: transfers root {}",
            e.transfersRoot
        ));
    }
    if selector == SettlementMintGate::InvalidVkHashes::SELECTOR
        && let Ok(e) = <SettlementMintGate::InvalidVkHashes as SolError>::abi_decode_raw(data)
    {
        return Some(format!(
            "InvalidVkHashes: null VK expected {} got {}, recursive VK expected {} got {}, inner VK expected {} got {}",
            e.expectedNullVkHash,
            e.actualNullVkHash,
            e.expectedRecursiveVkHash,
            e.actualRecursiveVkHash,
            e.expectedInnerVkHash,
            e.actualInnerVkHash
        ));
    }
    None
}

pub async fn preflight_vk_check<P>(
    provider: &P,
    gate: Address,
    null_vk_hash: FixedBytes<32>,
    recursive_vk_hash: FixedBytes<32>,
    inner_vk_hash: FixedBytes<32>,
) -> Result<()>
where
    P: Provider,
{
    let on_chain_null = provider
        .call(
            TransactionRequest::default()
                .with_to(gate)
                .with_input(SettlementMintGate::EXPECTED_NULL_VK_HASHCall {}.abi_encode()),
        )
        .decode_resp::<SettlementMintGate::EXPECTED_NULL_VK_HASHCall>()
        .into_future()
        .await
        .context("failed to read EXPECTED_NULL_VK_HASH")?
        .context("failed to decode EXPECTED_NULL_VK_HASH")?;
    let on_chain_recursive = provider
        .call(
            TransactionRequest::default()
                .with_to(gate)
                .with_input(SettlementMintGate::EXPECTED_RECURSIVE_VK_HASHCall {}.abi_encode()),
        )
        .decode_resp::<SettlementMintGate::EXPECTED_RECURSIVE_VK_HASHCall>()
        .into_future()
        .await
        .context("failed to read EXPECTED_RECURSIVE_VK_HASH")?
        .context("failed to decode EXPECTED_RECURSIVE_VK_HASH")?;
    let on_chain_inner = provider
        .call(
            TransactionRequest::default()
                .with_to(gate)
                .with_input(SettlementMintGate::EXPECTED_INNER_VK_HASHCall {}.abi_encode()),
        )
        .decode_resp::<SettlementMintGate::EXPECTED_INNER_VK_HASHCall>()
        .into_future()
        .await
        .context("failed to read EXPECTED_INNER_VK_HASH")?
        .context("failed to decode EXPECTED_INNER_VK_HASH")?;

    ensure!(
        on_chain_null == null_vk_hash,
        "null VK hash mismatch: on-chain {on_chain_null}, local {null_vk_hash}"
    );
    ensure!(
        on_chain_recursive == recursive_vk_hash,
        "recursive VK hash mismatch: on-chain {on_chain_recursive}, local {recursive_vk_hash}"
    );
    ensure!(
        on_chain_inner == inner_vk_hash,
        "inner VK hash mismatch: on-chain {on_chain_inner}, local {inner_vk_hash}"
    );
    Ok(())
}

async fn ensure_contract_code<P>(provider: &P, address: Address, label: &str) -> Result<()>
where
    P: Provider,
{
    let code = provider
        .get_code_at(address)
        .await
        .with_context(|| format!("failed to read {label} code"))?;
    ensure!(
        !code.is_empty(),
        "{label} is not deployed at {address}; rerun `cargo run --bin zktlsn -- fixture` against this Anvil"
    );
    Ok(())
}

async fn deploy_bytecode<P>(provider: &P, bytecode: Vec<u8>, label: &str) -> Result<Address>
where
    P: Provider,
{
    let pending = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(bytecode))
        .await
        .with_context(|| format!("failed to submit {label} deployment"))?;
    let receipt = pending
        .get_receipt()
        .await
        .with_context(|| format!("failed to fetch {label} deployment receipt"))?;

    ensure!(receipt.status(), "{label} deployment failed");
    receipt.contract_address().context(format!(
        "{label} deployment receipt did not include a contract address"
    ))
}

async fn transfer_token_ownership<P>(
    provider: &P,
    deployer: Address,
    token: Address,
    new_owner: Address,
) -> Result<()>
where
    P: Provider,
{
    let call = StableToken::transferOwnershipCall {
        newOwner: new_owner,
    };
    let pending = provider
        .send_transaction(
            TransactionRequest::default()
                .with_from(deployer)
                .with_to(token)
                .with_input(call.abi_encode()),
        )
        .await
        .context("failed to submit transferOwnership transaction")?;
    let receipt = pending
        .get_receipt()
        .await
        .context("failed to fetch transferOwnership receipt")?;
    ensure!(receipt.status(), "transferOwnership transaction failed");
    Ok(())
}

async fn read_token_owner<P>(provider: &P, token: Address) -> Result<Address>
where
    P: Provider,
{
    let response = provider
        .call(
            TransactionRequest::default()
                .with_to(token)
                .with_input(StableToken::ownerCall {}.abi_encode()),
        )
        .decode_resp::<StableToken::ownerCall>()
        .into_future()
        .await
        .context("owner call failed")?;
    response.context("failed to decode owner response")
}

fn append_constructor_args(bytecode: &[u8], constructor_args: Vec<u8>) -> Vec<u8> {
    bytecode.iter().copied().chain(constructor_args).collect()
}

fn link_verifier_bytecode(
    bytecode_template: &str,
    link_reference: &LinkReference,
    library_address: Address,
) -> Result<Vec<u8>> {
    let mut bytecode = bytecode_template
        .strip_prefix("0x")
        .context("verifier bytecode must be 0x-prefixed")?
        .to_string();
    let link_range = link_range(bytecode.len(), link_reference)?;
    bytecode.replace_range(link_range, &format!("{library_address:x}"));
    hex::decode(bytecode).context("failed to decode linked verifier bytecode")
}

fn link_range(bytecode_len: usize, reference: &LinkReference) -> Result<std::ops::Range<usize>> {
    let start = reference
        .start
        .checked_mul(2)
        .context("verifier link start overflow")?;
    let length = reference
        .length
        .checked_mul(2)
        .context("verifier link length overflow")?;
    let end = start
        .checked_add(length)
        .context("verifier link end overflow")?;
    ensure!(
        end <= bytecode_len,
        "verifier link reference is out of bounds for bytecode of length {}",
        bytecode_len / 2
    );
    Ok(start..end)
}

// ─── Artifact manifest persistence ─────────────────────────────────────────

pub fn load_generated_artifacts(repo_root: &Path) -> Result<PreparedArtifacts> {
    serde_json::from_slice::<DeploymentArtifactsFile>(
        &fs::read(repo_root.join(GENERATED_ARTIFACTS_PATH))
            .context("failed to read generated deployment artifacts")?,
    )
    .context("failed to decode generated deployment artifacts")?
    .try_into()
}

pub fn write_generated_artifacts(repo_root: &Path) -> Result<()> {
    let path = repo_root.join(GENERATED_ARTIFACTS_PATH);
    let manifest = build_artifacts_file(repo_root)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(&manifest)
        .context("failed to encode generated deployment artifacts")?;
    fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))
}

fn load_local_settlement_deployment(repo_root: &Path) -> Result<Option<SettlementDeployment>> {
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

fn write_local_settlement_deployment(
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
                "generated stable token bytecode",
            )?,
            settlement: PreparedSettlementArtifacts {
                verification_key: decode_hex(
                    &file.settlement_verification_key,
                    "generated settlement verification key",
                )?,
                verifier_library_bytecode: decode_hex(
                    &file.settlement_verifier_library_bytecode,
                    "generated settlement verifier library bytecode",
                )?,
                verifier_bytecode_template: file.settlement_verifier_bytecode_template,
                verifier_link_reference: file.settlement_verifier_link_reference,
                settlement_mint_gate_bytecode: decode_hex(
                    &file.settlement_mint_gate_bytecode,
                    "generated settlement mint gate bytecode",
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
