use std::net::SocketAddr;

use alloy::primitives::Address;
use anyhow::{Context, Result, ensure};
use quinn::Endpoint;
use server::app::TransferRequest;
use shared::TestQuicConfig;
use tracing::{info, instrument};

use crate::{
    attestation_proof::{AttestationProofFlow, run_attestation_proof_flow},
    live_demo::{DemoConnectionConfig, create_transfer, fetch_server_config},
    onchain_settlement::{
        connect_anvil, load_local_deployment, load_settlement_artifacts, mint_amount,
        preflight_vk_check, read_claimed_root, read_token_balance, repo_root, submit_proof_onchain,
    },
    recursive_batch::generate_settlement_bundle,
};

#[derive(Debug, Clone)]
pub struct SettlementArgs {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub verifier_addr: SocketAddr,
    pub from_users: Vec<String>,
    pub to_users: Vec<String>,
    pub amounts: Vec<u64>,
    pub anvil_rpc_url: String,
    pub anvil_private_key: String,
    pub mint_recipient: Option<Address>,
}

#[instrument(skip(args))]
pub async fn run_settlement(args: SettlementArgs) -> Result<()> {
    ensure!(
        !args.from_users.is_empty(),
        "settlement requires at least one transfer"
    );
    ensure!(
        args.from_users.len() == args.to_users.len() && args.to_users.len() == args.amounts.len(),
        "from-users, to-users, and amounts must have the same length"
    );

    let demo = DemoConnectionConfig {
        server_addr: args.server_addr,
        server_name: args.server_name.clone(),
    };
    info!("Fetching server configuration...");
    let server_config = fetch_server_config(&demo)
        .await
        .context("failed to fetch server configuration")?;

    let TestQuicConfig { client_config, .. } = shared::get_or_create_test_quic_config(
        std::path::Path::new("cert.pem"),
        std::path::Path::new("key.pem"),
    )
    .await
    .context("failed to load QUIC test configuration")?;
    let mut endpoint = Endpoint::client("[::]:0".parse().context("invalid client bind address")?)
        .context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let mut attestation_proofs = Vec::with_capacity(args.amounts.len());
    let mut total_amount = 0u64;
    let n = args.amounts.len();
    for (i, ((from_user, to_user), amount)) in args
        .from_users
        .iter()
        .zip(args.to_users.iter())
        .zip(args.amounts.iter().copied())
        .enumerate()
    {
        info!(i = i + 1, n, from = %from_user, to = %to_user, amount, "Creating transfer");
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
        info!(
            i = i + 1,
            n,
            tx_id = transfer.tx_id,
            "Generating attestation proof"
        );
        let proof_flow = connect_and_prove(&endpoint, &args, transfer.tx_id)
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
            .checked_add(amount)
            .context("settlement total amount overflow")?;
        attestation_proofs.push(proof_flow.bundle.native_proof);
    }

    let to_user_id = server_config.special_user_id;
    info!(
        count = attestation_proofs.len(),
        "Generating recursive settlement bundle"
    );
    let settlement_bundle = generate_settlement_bundle(&attestation_proofs, to_user_id)
        .context("failed to build settlement bundle")?;
    load_settlement_artifacts(&settlement_bundle.keccak_proof)
        .context("failed to load settlement deployment artifacts")?;
    let repo_root = repo_root().context("failed to resolve repo root")?;
    let (provider, deployer) = connect_anvil(&args.anvil_rpc_url, &args.anvil_private_key)
        .context("failed to connect to Anvil")?;
    let recipient = args.mint_recipient.unwrap_or(deployer);
    let contracts = load_local_deployment(&repo_root, &provider, settlement_bundle.state.to_user_id)
        .await
        .context("failed to load predeployed settlement contracts; run `cargo run --package zktlsn --release --example fixture` after starting Anvil")?;
    let balance_before = read_token_balance(&provider, contracts.token, recipient)
        .await
        .context("failed to read recipient token balance before settlement")?;

    info!("Running pre-flight VK hash check...");
    preflight_vk_check(
        &provider,
        contracts.gate,
        alloy::primitives::FixedBytes::from(settlement_bundle.state.null_vk_hash),
        alloy::primitives::FixedBytes::from(settlement_bundle.state.recursive_vk_hash),
        alloy::primitives::FixedBytes::from(settlement_bundle.state.inner_vk_hash),
    )
    .await
    .context("pre-flight VK hash check failed; circuits may need recompilation")?;

    info!("Submitting settlement proof on-chain...");
    let tx_hash = submit_proof_onchain(
        &provider,
        deployer,
        contracts.gate,
        &settlement_bundle.keccak_proof,
        recipient,
    )
    .await
    .context("failed to submit settlement transaction")?;

    ensure!(
        read_claimed_root(
            &provider,
            contracts.gate,
            settlement_bundle.state.transfers_root
        )
        .await
        .context("failed to read claimedRoot(transfersRoot)")?,
        "gate did not mark the settlement root as claimed"
    );
    let minted_balance = read_token_balance(&provider, contracts.token, recipient)
        .await
        .context("failed to read recipient token balance")?;
    let expected_balance = balance_before
        .checked_add(mint_amount(total_amount))
        .context("recipient token balance overflow")?;
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
        "Settlement completed successfully"
    );
    Ok(())
}

async fn connect_and_prove(
    endpoint: &Endpoint,
    args: &SettlementArgs,
    tx_id: u64,
) -> Result<AttestationProofFlow> {
    let connection = endpoint
        .connect(args.verifier_addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;

    run_attestation_proof_flow(
        tokio::io::join(recv, send),
        args.server_addr,
        &args.server_name,
        tx_id,
    )
    .await
}
