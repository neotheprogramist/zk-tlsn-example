use anyhow::{Context, Result};
use clap::Parser;

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
    bootstrap::run_main("settlement", || async {
        bootstrap::ensure_attestation_toolchain()
            .context("failed to prepare attestation toolchain")?;
        run(Cli::parse()).await
    })
    .await;
}

async fn run(cli: Cli) -> Result<()> {
    run_settlement(SettlementArgs {
        server_addr: cli.common.tlsn.server_addr,
        server_name: cli.common.tlsn.server_name,
        server_cert_path: cli.common.tlsn.server_cert_path,
        verifier_addr: cli.common.tlsn.verifier_addr,
        verifier_cert_path: cli.common.tlsn.verifier_cert_path,
        from_users: cli.from_users,
        to_users: cli.to_users,
        amounts: cli.amounts,
        anvil_rpc_url: cli.common.chain.anvil_rpc_url,
        anvil_private_key: cli.common.chain.anvil_private_key,
        mint_recipient: cli.common.chain.mint_recipient,
    })
    .await
}
