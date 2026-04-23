use std::{
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

use crate::artifacts::{
    self as artifacts, PreparedArtifacts, SettlementDeployment, load_generated_artifacts,
};

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
    proof: &zktlsn::KeccakProof,
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
    artifacts::write_local_settlement_deployment(repo_root, &deployment)
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
    let deployment = artifacts::load_local_settlement_deployment(repo_root)?
        .context("missing local settlement deployment manifest; run `cargo run --package zktlsn --release --example fixture` against this Anvil first")?;
    let chain_id = provider
        .get_chain_id()
        .await
        .context("failed to read chain id")?;
    ensure!(
        deployment.chain_id == chain_id,
        "local settlement deployment manifest targets chain id {}, current chain id is {}; rerun `cargo run --package zktlsn --release --example fixture`",
        deployment.chain_id,
        chain_id
    );
    ensure!(
        deployment.expected_to_user_id == expected_to_user_id,
        "local settlement deployment expected to_user_id {}, but current server special user id is {}; rerun `cargo run --package zktlsn --release --example fixture`",
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
    proof: &zktlsn::KeccakProof,
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
        "{label} is not deployed at {address}; rerun `cargo run --package zktlsn --release --example fixture` against this Anvil"
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
    link_reference: &artifacts::LinkReference,
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

fn link_range(
    bytecode_len: usize,
    reference: &artifacts::LinkReference,
) -> Result<std::ops::Range<usize>> {
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
