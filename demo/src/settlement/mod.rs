pub mod chain;
mod fixture;

use std::{net::SocketAddr, path::PathBuf};

use alloy::{
    hex,
    primitives::{Address, FixedBytes, U256},
    providers::Provider,
};
use anyhow::{Context, Result, ensure};
use chain::{
    OnchainContracts, connect_anvil, load_local_deployment, load_settlement_artifacts, mint_amount,
    preflight_vk_check, read_claimed_root, read_token_balance, repo_root, submit_proof_onchain,
};
pub use fixture::prepare_settlement_artifacts;
use quinn::Endpoint;
use serde_json::json;
use tracing::{info, instrument};
use zktlsn_core::zk::{
    PaddingConfig, Proof, RecursiveSettlement, aggregate_attestations, prove_attestation,
};

use crate::{
    ledger::{ServerConfigResponse, TransferRequest},
    transport::{
        DemoConnectionConfig, connect_and_attest, create_transfer, fetch_server_config,
        open_client_endpoint,
    },
};

#[derive(Debug, Clone)]
pub struct SettlementArgs {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub server_cert_path: PathBuf,
    pub verifier_addr: SocketAddr,
    pub verifier_cert_path: PathBuf,
    pub from_users: Vec<String>,
    pub to_users: Vec<String>,
    pub amounts: Vec<u64>,
    pub anvil_rpc_url: String,
    pub anvil_private_key: String,
    pub mint_recipient: Address,
}

#[instrument(skip(args))]
pub async fn run_settlement(args: SettlementArgs) -> Result<()> {
    ensure_balanced_batch(&args)?;
    let total_amount = sum_amounts(&args.amounts)?;

    let demo = DemoConnectionConfig {
        server_addr: args.server_addr,
        server_name: args.server_name.clone(),
        server_cert_path: args.server_cert_path.clone(),
    };
    info!("Fetching server configuration...");
    let server_config = fetch_server_config(&demo)
        .await
        .context("failed to fetch server configuration")?;

    let endpoint = open_client_endpoint(&args.verifier_cert_path).await?;
    let attestation_proofs =
        collect_attestation_proofs(&endpoint, &args, &demo, &server_config).await?;

    let to_user_id = server_config.special_user_id;
    info!(
        count = attestation_proofs.len(),
        "Generating recursive settlement bundle"
    );
    let num_attestations = attestation_proofs.len();
    let settlement = aggregate_attestations(&attestation_proofs, to_user_id)
        .context("failed to aggregate attestation proofs")?;
    load_settlement_artifacts(&repo_root()?, &settlement.keccak_proof)
        .context("failed to load settlement deployment artifacts")?;

    submit_and_verify_settlement(&args, &settlement, total_amount, num_attestations).await
}

fn ensure_balanced_batch(args: &SettlementArgs) -> Result<()> {
    ensure!(
        !args.from_users.is_empty(),
        "settlement requires at least one transfer"
    );
    ensure!(
        args.from_users.len() == args.to_users.len() && args.to_users.len() == args.amounts.len(),
        "from-users, to-users, and amounts must have the same length"
    );
    Ok(())
}

fn sum_amounts(amounts: &[u64]) -> Result<u64> {
    amounts
        .iter()
        .try_fold(0u64, |acc, amount| acc.checked_add(*amount))
        .context("settlement total amount overflow")
}

async fn collect_attestation_proofs(
    endpoint: &Endpoint,
    args: &SettlementArgs,
    demo: &DemoConnectionConfig,
    server_config: &ServerConfigResponse,
) -> Result<Vec<Proof>> {
    let n = args.amounts.len();
    let mut attestation_proofs = Vec::with_capacity(n);
    for (i, ((from_user, to_user), amount)) in args
        .from_users
        .iter()
        .zip(args.to_users.iter())
        .zip(args.amounts.iter().copied())
        .enumerate()
    {
        info!(i = i + 1, n, from = %from_user, to = %to_user, amount, "Creating transfer");
        let transfer = create_transfer(
            demo,
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
            "Notarising transfer (TLSN attest-only)"
        );
        let flow = connect_and_attest(
            endpoint,
            args.verifier_addr,
            args.server_addr,
            &args.server_name,
            &args.server_cert_path,
            transfer.tx_id,
        )
        .await
        .with_context(|| {
            format!(
                "failed to complete TLSN attestation flow for tx {}",
                transfer.tx_id
            )
        })?;
        ensure!(
            flow.verification.is_success(),
            "notarisation failed for tx {}: {}",
            transfer.tx_id,
            flow.verification.message()
        );

        info!(
            i = i + 1,
            n,
            tx_id = transfer.tx_id,
            "Generating per-transfer ZK proof"
        );
        let attestation_proof = prove_attestation(
            &flow.transcript_commitments,
            &flow.transcript_secrets,
            &flow.received_transcript,
            PaddingConfig::new(zktlsn_core::ATTESTATION_LEN),
        )
        .with_context(|| format!("failed to generate ZK proof for tx {}", transfer.tx_id))?;
        attestation_proofs.push(attestation_proof.native_proof);
    }
    Ok(attestation_proofs)
}

async fn submit_and_verify_settlement(
    args: &SettlementArgs,
    settlement: &RecursiveSettlement,
    total_amount: u64,
    num_attestations: usize,
) -> Result<()> {
    let repo_root = repo_root().context("failed to resolve repo root")?;
    let (provider, deployer) = connect_anvil(&args.anvil_rpc_url, &args.anvil_private_key)
        .context("failed to connect to Anvil")?;
    let recipient = args.mint_recipient;
    let contracts = load_local_deployment(&repo_root, &provider, settlement.state.to_user_id)
        .await
        .context("failed to load predeployed settlement contracts; run the fixture subcommand after starting Anvil")?;
    let balance_before = read_token_balance(&provider, contracts.token, recipient)
        .await
        .context("failed to read recipient token balance before settlement")?;

    info!("Running pre-flight VK hash check...");
    preflight_vk_check(
        &provider,
        contracts.gate,
        FixedBytes::from(settlement.state.null_vk_hash),
        FixedBytes::from(settlement.state.recursive_vk_hash),
        FixedBytes::from(settlement.state.inner_vk_hash),
    )
    .await
    .context("pre-flight VK hash check failed; circuits may need recompilation")?;

    info!("Submitting settlement proof on-chain...");
    let tx_hash = submit_proof_onchain(
        &provider,
        deployer,
        contracts.gate,
        &settlement.keccak_proof,
        recipient,
    )
    .await
    .context("failed to submit settlement transaction")?;

    let balance_after = ensure_claim_and_balance(
        &provider,
        &contracts,
        settlement.state.transfers_root,
        recipient,
        balance_before,
        total_amount,
    )
    .await?;

    info!(
        total_amount,
        verifier = %contracts.verifier,
        token = %contracts.token,
        gate = %contracts.gate,
        recipient = %recipient,
        tx_hash = %tx_hash,
        "Settlement completed successfully"
    );

    let result = json!({
        "flow": "settle",
        "num_attestations": num_attestations,
        "total_amount": total_amount,
        "to_user_id": settlement.state.to_user_id,
        "transfers_root": format!("0x{}", hex::encode(settlement.state.transfers_root)),
        "null_vk_hash": format!("0x{}", hex::encode(settlement.state.null_vk_hash)),
        "recursive_vk_hash": format!("0x{}", hex::encode(settlement.state.recursive_vk_hash)),
        "inner_vk_hash": format!("0x{}", hex::encode(settlement.state.inner_vk_hash)),
        "claimed_root": true,
        "balance_before": balance_before.to_string(),
        "balance_after": balance_after.to_string(),
        "balance_delta": mint_amount(total_amount).to_string(),
        "recipient": format!("{recipient}"),
        "tx_hash": format!("{tx_hash}"),
    });
    println!("ZKTLSN_RESULT {result}");
    Ok(())
}

async fn ensure_claim_and_balance<P: Provider>(
    provider: &P,
    contracts: &OnchainContracts,
    transfers_root: [u8; 32],
    recipient: Address,
    balance_before: U256,
    total_amount: u64,
) -> Result<U256> {
    ensure!(
        read_claimed_root(provider, contracts.gate, transfers_root)
            .await
            .context("failed to read claimedRoot(transfersRoot)")?,
        "gate did not mark the settlement root as claimed"
    );
    let minted_balance = read_token_balance(provider, contracts.token, recipient)
        .await
        .context("failed to read recipient token balance")?;
    let expected_balance = balance_before
        .checked_add(mint_amount(total_amount))
        .context("recipient token balance overflow")?;
    ensure!(
        minted_balance == expected_balance,
        "unexpected token balance: expected {expected_balance}, got {minted_balance}"
    );
    Ok(minted_balance)
}
