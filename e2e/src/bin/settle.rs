use anyhow::Result;
use clap::Parser;
use tracing::error;

use e2e::{
    bootstrap,
    cli::CommonCli,
    settle::{SettlementArgs, run_settlement},
};

#[derive(Debug, Parser)]
#[command(
    about = "Create one or more fiat transfers, collect verifier-signed tickets, and mint one onchain settlement"
)]
struct Cli {
    #[command(flatten)]
    common: CommonCli,
    #[arg(
        long,
        env = "ZKTLSN_BATCH_FROM_USERS",
        num_args = 1..,
        value_delimiter = ','
    )]
    from_users: Vec<String>,
    #[arg(
        long,
        env = "ZKTLSN_BATCH_TO_USERS",
        num_args = 1..,
        value_delimiter = ','
    )]
    to_users: Vec<String>,
    #[arg(
        long,
        env = "ZKTLSN_BATCH_AMOUNTS",
        num_args = 1..,
        value_delimiter = ','
    )]
    amounts: Vec<u64>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    bootstrap::init_logging().expect("failed to initialize logging");
    bootstrap::ensure_attestation_toolchain().expect("failed to prepare attestation toolchain");

    if let Err(error) = run(Cli::parse()).await {
        error!(error = %format!("{error:#}"), "settlement flow failed");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    run_settlement(SettlementArgs {
        server_addr: cli.common.server_addr,
        server_name: cli.common.server_name,
        server_cert_path: cli.common.server_cert_path,
        verifier_addr: cli.common.verifier_addr,
        verifier_cert_path: cli.common.verifier_cert_path,
        from_users: cli.from_users,
        to_users: cli.to_users,
        amounts: cli.amounts,
        anvil_rpc_url: cli.common.anvil_rpc_url,
        anvil_private_key: cli.common.anvil_private_key,
        mint_recipient: cli.common.mint_recipient,
    })
    .await
}
