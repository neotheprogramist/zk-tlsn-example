#[path = "support/attestation_proof.rs"]
mod attestation_proof;
#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;
#[path = "support/live_demo.rs"]
mod live_demo;
#[path = "support/recursive_batch.rs"]
mod recursive_batch;

use std::{future::IntoFuture, net::SocketAddr};

use alloy::{
    hex,
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder},
    primitives::{Address, FixedBytes, TxHash, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::{SolCall, SolConstructor};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use quinn::Endpoint;
use server::app::TransferRequest;
use shared::{TestQuicConfig, init_logging};
use tracing::{error, info, instrument};

use crate::{
    attestation_proof::{AttestationProofFlow, run_attestation_proof_flow},
    deployment_artifacts::load_embedded_artifacts,
    live_demo::{DemoConnectionConfig, create_transfer, fetch_server_config},
    recursive_batch::generate_batch_recursive_bundle,
};

const DEFAULT_ANVIL_RPC_URL: &str = "http://127.0.0.1:8545";
const DEFAULT_ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

sol! {
    contract StableToken {
        constructor(address initialOwner);
        function transferOwnership(address newOwner) external;
        function owner() external view returns (address owner);
        function balanceOf(address account) external view returns (uint256 balance);
    }

    contract BatchMintGate {
        constructor(
            address verifier_,
            address token_,
            uint256 expectedToUserId_,
            bytes32 expectedNullVkHash_,
            bytes32 expectedRecursiveVkHash_
        );
        function batchMint(bytes calldata proof, bytes32[] calldata publicInputs, address recipient) external;
        function claimedRoot(bytes32 transfersRoot) external view returns (bool claimed);
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    about = "Create a batch of fiat transfers, recursively aggregate their proofs, and mint one onchain settlement"
)]
struct Cli {
    /// TLS ledger server address.
    #[arg(long, env = "ZKTLSN_SERVER_ADDR", default_value = "127.0.0.1:8443")]
    server_addr: SocketAddr,
    /// Expected TLS server name for the attestation fetch.
    #[arg(long, env = "ZKTLSN_SERVER_NAME", default_value = "localhost")]
    server_name: String,
    /// Off-chain verifier address used for native proof checks.
    #[arg(long, env = "ZKTLSN_VERIFIER_ADDR", default_value = "[::1]:5000")]
    verifier_addr: SocketAddr,
    /// Comma-delimited source usernames for the batch. Must match `--to-users` and `--amounts` in length.
    #[arg(
        long,
        env = "ZKTLSN_BATCH_FROM_USERS",
        num_args = 1..,
        value_delimiter = ',',
        default_value = "alice,bob,alice"
    )]
    from_users: Vec<String>,
    /// Comma-delimited destination usernames for the batch. All entries must resolve to the special user for mint eligibility.
    #[arg(
        long,
        env = "ZKTLSN_BATCH_TO_USERS",
        num_args = 1..,
        value_delimiter = ',',
        default_value = "treasury,treasury,treasury"
    )]
    to_users: Vec<String>,
    /// Comma-delimited transfer amounts for the batch, in fiat units.
    #[arg(
        long,
        env = "ZKTLSN_BATCH_AMOUNTS",
        num_args = 1..,
        value_delimiter = ',',
        default_value = "25,10,15"
    )]
    amounts: Vec<u64>,
    /// Anvil JSON-RPC endpoint used for deployment and minting.
    #[arg(long, env = "ZKTLSN_ANVIL_RPC_URL", default_value = DEFAULT_ANVIL_RPC_URL)]
    anvil_rpc_url: String,
    /// Private key for the deployment account on Anvil.
    #[arg(
        long,
        env = "ZKTLSN_ANVIL_PRIVATE_KEY",
        default_value = DEFAULT_ANVIL_PRIVATE_KEY
    )]
    anvil_private_key: String,
    /// Optional token recipient. Defaults to the deployer account when omitted.
    #[arg(long, env = "ZKTLSN_MINT_RECIPIENT")]
    mint_recipient: Option<Address>,
}

#[derive(Clone, Copy)]
struct OnchainContracts {
    verifier: Address,
    token: Address,
    gate: Address,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    zktlsn::setup_cached_barretenberg_srs().expect(
        "failed to setup cached Barretenberg SRS; run `cargo run --package zktlsn --release --example fixture` first",
    );
    init_logging("info");

    if let Err(error) = run(Cli::parse()).await {
        error!(error = %format!("{error:#}"), "batch settle flow failed");
        std::process::exit(1);
    }
}

#[instrument(skip(cli))]
async fn run(cli: Cli) -> Result<()> {
    ensure!(
        !cli.from_users.is_empty(),
        "batch settlement requires at least one transfer"
    );
    ensure!(
        cli.from_users.len() == cli.to_users.len() && cli.to_users.len() == cli.amounts.len(),
        "from-users, to-users, and amounts must have the same length"
    );

    let demo = DemoConnectionConfig {
        server_addr: cli.server_addr,
        server_name: cli.server_name.clone(),
    };
    let server_config = fetch_server_config(&demo)
        .await
        .context("failed to fetch server configuration")?;

    let mut noir_inputs = Vec::with_capacity(cli.amounts.len());
    let mut total_amount = 0u64;
    for ((from_user, to_user), amount) in cli
        .from_users
        .iter()
        .zip(cli.to_users.iter())
        .zip(cli.amounts.iter().copied())
    {
        let transfer = create_transfer(
            &demo,
            &TransferRequest {
                from_username: from_user.clone(),
                to_username: to_user.clone(),
                amount,
            },
        )
        .await
        .with_context(|| format!("failed to create transfer for {from_user}->{to_user}"))?;
        ensure!(
            transfer.eligible_for_mint,
            "transfer tx {} is not eligible for minting: destination user '{}' (id {}) does not match configured special user '{}' (id {})",
            transfer.tx_id,
            transfer.to_username,
            transfer.to_user_id,
            server_config.special_username,
            server_config.special_user_id
        );
        let proof_flow = connect_and_prove(&cli, transfer.tx_id)
            .await
            .with_context(|| {
                format!(
                    "failed to complete attestation proof flow for tx {}",
                    transfer.tx_id
                )
            })?;
        ensure!(
            proof_flow.verification.success,
            "verification failed for tx {}: {}",
            transfer.tx_id,
            proof_flow.verification.message
        );
        total_amount = total_amount
            .checked_add(proof_flow.bundle.noir_inputs.amount)
            .context("batch total amount overflow")?;
        noir_inputs.push(proof_flow.bundle.noir_inputs);
    }

    let batch_bundle = generate_batch_recursive_bundle(&noir_inputs)
        .context("failed to build recursive batch settlement bundle")?;
    let artifacts = load_batch_deployment_artifacts(&batch_bundle.keccak_proof)
        .context("failed to load batch deployment artifacts")?;
    let (provider, deployer) = connect_anvil(&cli.anvil_rpc_url, &cli.anvil_private_key)
        .context("failed to connect to Anvil")?;
    let recipient = cli.mint_recipient.unwrap_or(deployer);
    let contracts = deploy_contracts(
        &provider,
        deployer,
        &artifacts,
        batch_bundle.state.to_user_id,
        batch_bundle.state.allowed_null_vk_hash,
        batch_bundle.state.allowed_recursive_vk_hash,
    )
    .await
    .context("failed to deploy batch settlement contracts")?;
    let tx_hash = submit_proof_onchain(
        &provider,
        deployer,
        contracts.gate,
        &batch_bundle.keccak_proof,
        recipient,
    )
    .await
    .context("failed to submit batch settlement transaction")?;

    ensure!(
        read_claimed_root(&provider, contracts.gate, batch_bundle.state.transfers_root)
            .await
            .context("failed to read claimedRoot(transfersRoot)")?,
        "gate did not mark the batch transfers root as claimed"
    );
    let minted_balance = read_token_balance(&provider, contracts.token, recipient)
        .await
        .context("failed to read recipient token balance")?;
    let expected_balance = mint_amount(total_amount);
    ensure!(
        minted_balance == expected_balance,
        "unexpected token balance: expected {expected_balance}, got {minted_balance}"
    );

    info!(
        total_amount,
        verifier = %contracts.verifier,
        token = %contracts.token,
        gate = %contracts.gate,
        recipient = %recipient,
        tx_hash = %tx_hash,
        "Batch settlement completed successfully"
    );
    Ok(())
}

async fn connect_and_prove(cli: &Cli, tx_id: u64) -> Result<AttestationProofFlow> {
    let TestQuicConfig { client_config, .. } = shared::get_or_create_test_quic_config(
        std::path::Path::new("cert.pem"),
        std::path::Path::new("key.pem"),
    )
    .await
    .context("failed to load QUIC test configuration")?;
    let mut endpoint = Endpoint::client("[::]:0".parse().context("invalid client bind address")?)
        .context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(cli.verifier_addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;

    run_attestation_proof_flow(
        tokio::io::join(recv, send),
        cli.server_addr,
        &cli.server_name,
        tx_id,
    )
    .await
}

fn connect_anvil(rpc_url: &str, private_key: &str) -> Result<(impl Provider, Address)> {
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

fn load_batch_deployment_artifacts(
    proof: &zktlsn::KeccakProof,
) -> Result<deployment_artifacts::PreparedBatchArtifacts> {
    let artifacts = load_embedded_artifacts()?.batch;
    ensure!(
        artifacts.verification_key == proof.verification_key,
        "embedded batch deployment artifacts do not match the generated recursive keccak verification key; rerun `cargo run --package zktlsn --release --example fixture` and rebuild the `settle_batch` binary"
    );
    Ok(artifacts)
}

async fn deploy_contracts<P>(
    provider: &P,
    deployer: Address,
    artifacts: &deployment_artifacts::PreparedBatchArtifacts,
    special_user_id: u64,
    null_vk_hash: [u8; 32],
    recursive_vk_hash: [u8; 32],
) -> Result<OnchainContracts>
where
    P: Provider,
{
    let library = deploy_bytecode(
        provider,
        artifacts.verifier_library_bytecode.clone(),
        "recursive verifier library",
    )
    .await?;
    let verifier_bytecode = link_verifier_bytecode(
        &artifacts.verifier_bytecode_template,
        &artifacts.verifier_link_reference,
        library,
    )
    .context("failed to link recursive verifier bytecode")?;
    let verifier = deploy_bytecode(provider, verifier_bytecode, "recursive verifier").await?;

    let token_constructor = StableToken::constructorCall {
        initialOwner: deployer,
    };
    let token = deploy_bytecode(
        provider,
        append_constructor_args(
            &load_embedded_artifacts()?.stable_token_bytecode,
            token_constructor.abi_encode(),
        ),
        "stable token",
    )
    .await?;

    let gate_constructor = BatchMintGate::constructorCall {
        verifier_: verifier,
        token_: token,
        expectedToUserId_: U256::from(special_user_id),
        expectedNullVkHash_: FixedBytes::<32>::from(null_vk_hash),
        expectedRecursiveVkHash_: FixedBytes::<32>::from(recursive_vk_hash),
    };
    let gate = deploy_bytecode(
        provider,
        append_constructor_args(
            &artifacts.batch_mint_gate_bytecode,
            gate_constructor.abi_encode(),
        ),
        "batch mint gate",
    )
    .await?;

    transfer_token_ownership(provider, deployer, token, gate)
        .await
        .context("failed to transfer token ownership to batch gate")?;
    ensure!(
        read_token_owner(provider, token)
            .await
            .context("failed to read token owner")?
            == gate,
        "stable token owner was not updated to the batch gate contract"
    );

    Ok(OnchainContracts {
        verifier,
        token,
        gate,
    })
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

async fn submit_proof_onchain<P>(
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
    let call = BatchMintGate::batchMintCall {
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
        .context("failed to submit batchMint transaction")?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .context("failed to fetch batchMint receipt")?;
    ensure!(
        receipt.status(),
        "batchMint transaction reverted: {tx_hash}"
    );
    Ok(tx_hash)
}

async fn read_claimed_root<P>(provider: &P, gate: Address, root: [u8; 32]) -> Result<bool>
where
    P: Provider,
{
    let response = provider
        .call(
            TransactionRequest::default().with_to(gate).with_input(
                BatchMintGate::claimedRootCall {
                    transfersRoot: FixedBytes::<32>::from(root),
                }
                .abi_encode(),
            ),
        )
        .decode_resp::<BatchMintGate::claimedRootCall>()
        .into_future()
        .await
        .context("claimedRoot call failed")?;
    response.context("failed to decode claimedRoot response")
}

async fn read_token_balance<P>(provider: &P, token: Address, account: Address) -> Result<U256>
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

fn mint_amount(amount: u64) -> U256 {
    U256::from(amount) * U256::from(1_000_000_000_000_000_000_u128)
}

fn append_constructor_args(bytecode: &[u8], constructor_args: Vec<u8>) -> Vec<u8> {
    bytecode.iter().copied().chain(constructor_args).collect()
}

fn link_verifier_bytecode(
    bytecode_template: &str,
    link_reference: &deployment_artifacts::LinkReference,
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
    reference: &deployment_artifacts::LinkReference,
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
