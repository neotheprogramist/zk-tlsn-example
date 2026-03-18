#[path = "support/attestation_proof.rs"]
mod attestation_proof;
#[path = "support/live_demo.rs"]
mod live_demo;

use std::net::SocketAddr;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use quinn::Endpoint;
use server::app::TransferRequest;
use shared::{TestQuicConfig, init_logging};
use tracing::{error, info, instrument};
use verifier::VerificationOutcome;

use crate::{
    attestation_proof::run_attestation_proof_flow,
    live_demo::{DemoConnectionConfig, create_transfer},
};

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
}

fn main() {
    zktlsn::ensure_cli_toolchain().expect("failed to validate nargo/bb CLI toolchain");
    zktlsn::compile_attestation_package().expect("failed to compile the attestation circuit");
    init_logging("info");

    smol::block_on(async {
        if let Err(err) = run(Cli::parse()).await {
            error!(error = %format!("{err:#}"), "prover flow failed");
            std::process::exit(1);
        }
    });
}

#[instrument(skip(cli))]
async fn run(cli: Cli) -> Result<()> {
    let demo = DemoConnectionConfig {
        server_addr: cli.server_addr,
        server_name: cli.server_name.clone(),
    };
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
    let verification = connect_and_prove(&cli, transfer.tx_id)
        .await
        .context("failed to complete TLSN proof flow")?;

    ensure!(
        verification.success,
        "verification failed: {}",
        verification.message
    );
    info!(
        tx_id = transfer.tx_id,
        to_user_id = transfer.to_user_id,
        eligible_for_mint = transfer.eligible_for_mint,
        verified_fields = ?verification.verified_fields,
        "Native transfer proof verified successfully"
    );
    Ok(())
}

async fn connect_and_prove(cli: &Cli, tx_id: u64) -> Result<VerificationOutcome> {
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
    .map(|flow| flow.verification)
}
