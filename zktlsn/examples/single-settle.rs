#[path = "support/attestation_proof.rs"]
mod attestation_proof;
#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;
#[path = "support/live_demo.rs"]
mod live_demo;
#[path = "support/onchain_settlement.rs"]
mod onchain_settlement;
#[path = "support/recursive_batch.rs"]
mod recursive_batch;
#[path = "support/settlement_demo.rs"]
mod settlement_demo;

use std::net::SocketAddr;

use alloy::primitives::Address;
use anyhow::Result;
use clap::Parser;
use shared::init_logging;
use tracing::error;

use crate::{
    onchain_settlement::{DEFAULT_ANVIL_PRIVATE_KEY, DEFAULT_ANVIL_RPC_URL},
    settlement_demo::{SettlementArgs, run_settlement},
};

#[derive(Debug, Clone, Parser)]
#[command(
    about = "Create one fiat transfer and submit it through the canonical settlement pipeline"
)]
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    zktlsn::ensure_cli_toolchain().expect("failed to validate nargo/bb CLI toolchain");
    zktlsn::compile_attestation_package().expect("failed to compile the attestation circuit");
    init_logging("info");

    if let Err(error) = run(Cli::parse()).await {
        error!(error = %format!("{error:#}"), "single settlement flow failed");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    run_settlement(SettlementArgs {
        server_addr: cli.server_addr,
        server_name: cli.server_name,
        verifier_addr: cli.verifier_addr,
        from_users: vec![cli.from_user],
        to_users: vec![cli.to_user],
        amounts: vec![cli.amount],
        anvil_rpc_url: cli.anvil_rpc_url,
        anvil_private_key: cli.anvil_private_key,
        mint_recipient: cli.mint_recipient,
    })
    .await
}
