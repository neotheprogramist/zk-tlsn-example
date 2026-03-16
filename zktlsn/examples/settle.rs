#[path = "support/attestation_proof.rs"]
mod attestation_proof;
#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;
#[path = "support/live_demo.rs"]
mod live_demo;

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
    deployment_artifacts::{PreparedArtifacts, load_embedded_artifacts},
    live_demo::{DemoConnectionConfig, create_transfer, fetch_server_config},
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

    contract StableMintGate {
        constructor(address verifier_, address token_, uint256 expectedToUserId_);
        function proveAndMint(bytes calldata proof, bytes32[] calldata publicInputs, address recipient) external;
        function claimedTxId(uint256 txId) external view returns (bool claimed);
        function expectedToUserId() external view returns (uint256 expected);
    }
}

#[derive(Debug, Clone, Parser)]
struct Cli {
    #[arg(long, env = "ZKTLSN_SERVER_ADDR", default_value = "127.0.0.1:8443")]
    server_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVER_NAME", default_value = "localhost")]
    server_name: String,
    #[arg(long, env = "ZKTLSN_VERIFIER_ADDR", default_value = "[::1]:5000")]
    verifier_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_FROM_USER", default_value = "alice")]
    from_user: String,
    #[arg(long, env = "ZKTLSN_TO_USER", default_value = "treasury")]
    to_user: String,
    #[arg(long, env = "ZKTLSN_TRANSFER_AMOUNT", default_value_t = 25)]
    amount: u64,
    #[arg(long, env = "ZKTLSN_ANVIL_RPC_URL", default_value = DEFAULT_ANVIL_RPC_URL)]
    anvil_rpc_url: String,
    #[arg(
        long,
        env = "ZKTLSN_ANVIL_PRIVATE_KEY",
        default_value = DEFAULT_ANVIL_PRIVATE_KEY
    )]
    anvil_private_key: String,
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
    zktlsn::setup_barretenberg_srs().expect("failed to setup Barretenberg SRS");
    init_logging("info");

    if let Err(error) = run(Cli::parse()).await {
        error!(error = %format!("{error:#}"), "settle flow failed");
        std::process::exit(1);
    }
}

#[instrument(skip(cli))]
async fn run(cli: Cli) -> Result<()> {
    let demo = DemoConnectionConfig {
        server_addr: cli.server_addr,
        server_name: cli.server_name.clone(),
    };
    let server_config = fetch_server_config(&demo)
        .await
        .context("failed to fetch server configuration")?;
    let transfer = create_transfer(
        &demo,
        &TransferRequest {
            from_username: cli.from_user.clone(),
            to_username: cli.to_user.clone(),
            amount: cli.amount,
        },
    )
    .await
    .context("failed to create transfer attestation")?;
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
        .context("failed to complete attestation proof flow")?;

    ensure!(
        proof_flow.verification.success,
        "verification failed: {}",
        proof_flow.verification.message
    );

    let artifacts =
        load_deployment_artifacts(&proof_flow).context("failed to load deployment artifacts")?;
    let (provider, deployer) = connect_anvil(&cli.anvil_rpc_url, &cli.anvil_private_key)
        .context("failed to connect to Anvil")?;
    let recipient = cli.mint_recipient.unwrap_or(deployer);
    let contracts = deploy_contracts(
        &provider,
        deployer,
        &artifacts,
        server_config.special_user_id,
    )
    .await
    .context("failed to deploy settlement contracts")?;
    let tx_hash = submit_proof_onchain(
        &provider,
        deployer,
        contracts.gate,
        &proof_flow.bundle.keccak_proof,
        recipient,
    )
    .await
    .context("failed to submit settlement transaction")?;

    ensure!(
        read_claimed_tx_id(&provider, contracts.gate, transfer.tx_id)
            .await
            .context("failed to read claimedTxId(txId)")?,
        "gate did not mark tx_id {} as claimed",
        transfer.tx_id
    );
    let minted_balance = read_token_balance(&provider, contracts.token, recipient)
        .await
        .context("failed to read recipient token balance")?;
    let expected_balance = mint_amount(transfer.amount);
    ensure!(
        minted_balance == expected_balance,
        "unexpected token balance: expected {expected_balance}, got {minted_balance}"
    );

    info!(
        tx_id = transfer.tx_id,
        to_user_id = transfer.to_user_id,
        eligible_for_mint = transfer.eligible_for_mint,
        special_user_id = server_config.special_user_id,
        verifier = %contracts.verifier,
        token = %contracts.token,
        gate = %contracts.gate,
        recipient = %recipient,
        tx_hash = %tx_hash,
        "Stablecoin settlement completed successfully"
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

fn load_deployment_artifacts(flow: &AttestationProofFlow) -> Result<PreparedArtifacts> {
    let artifacts = load_embedded_artifacts()?;
    ensure!(
        artifacts.verification_key == flow.bundle.keccak_proof.verification_key,
        "embedded deployment artifacts do not match the generated keccak verification key; rerun `cargo run --package zktlsn --release --example fixture` and rebuild the `settle` binary"
    );
    Ok(artifacts)
}

async fn deploy_contracts<P>(
    provider: &P,
    deployer: Address,
    artifacts: &PreparedArtifacts,
    special_user_id: u64,
) -> Result<OnchainContracts>
where
    P: Provider,
{
    let library = deploy_bytecode(
        provider,
        artifacts.verifier_library_bytecode.clone(),
        "verifier library",
    )
    .await?;
    let verifier_bytecode = link_verifier_bytecode(
        &artifacts.verifier_bytecode_template,
        &artifacts.verifier_link_reference,
        library,
    )
    .context("failed to link verifier bytecode")?;
    let verifier = deploy_bytecode(provider, verifier_bytecode, "verifier").await?;

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

    let gate_constructor = StableMintGate::constructorCall {
        verifier_: verifier,
        token_: token,
        expectedToUserId_: U256::from(special_user_id),
    };
    let gate = deploy_bytecode(
        provider,
        append_constructor_args(
            &artifacts.stable_mint_gate_bytecode,
            gate_constructor.abi_encode(),
        ),
        "stable mint gate",
    )
    .await?;

    transfer_token_ownership(provider, deployer, token, gate)
        .await
        .context("failed to transfer token ownership to gate")?;
    ensure!(
        read_token_owner(provider, token)
            .await
            .context("failed to read token owner")?
            == gate,
        "stable token owner was not updated to the gate contract"
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
    let call = StableMintGate::proveAndMintCall {
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
        .context("failed to submit proveAndMint transaction")?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .context("failed to fetch proveAndMint receipt")?;
    ensure!(
        receipt.status(),
        "proveAndMint transaction reverted: {tx_hash}"
    );
    Ok(tx_hash)
}

async fn read_claimed_tx_id<P>(provider: &P, gate: Address, tx_id: u64) -> Result<bool>
where
    P: Provider,
{
    let response = provider
        .call(
            TransactionRequest::default().with_to(gate).with_input(
                StableMintGate::claimedTxIdCall {
                    txId: U256::from(tx_id),
                }
                .abi_encode(),
            ),
        )
        .decode_resp::<StableMintGate::claimedTxIdCall>()
        .into_future()
        .await
        .context("claimedTxId call failed")?;
    response.context("failed to decode claimedTxId response")
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
