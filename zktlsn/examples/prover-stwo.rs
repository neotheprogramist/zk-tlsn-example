#[path = "support/attestation_proof_stwo.rs"]
mod attestation_proof_stwo;
#[path = "support/live_demo.rs"]
mod live_demo;

use std::net::SocketAddr;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use quinn::Endpoint;
use server::app::TransferRequest;
use shared::{TestQuicConfig, init_logging};
use tracing::{error, info, instrument};

use crate::{
    attestation_proof_stwo::run_stwo_attestation_proof_flow,
    live_demo::{DemoConnectionConfig, create_transfer},
};

#[derive(Debug, Clone, Parser)]
struct Args {
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
    init_logging("info");

    let args = Args::parse();

    smol::block_on(async {
        if let Err(err) = run(
            args.server_addr,
            args.server_name,
            args.verifier_addr,
            args.from_user,
            args.to_user,
            args.amount,
        )
        .await
        {
            error!(error = %format!("{err:#}"), "STWO prover flow failed");
            std::process::exit(1);
        }
    });
}

#[instrument(skip(server_name, from_user, to_user))]
async fn run(
    server_addr: SocketAddr,
    server_name: String,
    verifier_addr: SocketAddr,
    from_user: String,
    to_user: String,
    amount: u64,
) -> Result<()> {
    let demo = DemoConnectionConfig {
        server_addr,
        server_name: server_name.clone(),
    };
    let transfer = create_transfer(
        &demo,
        &TransferRequest {
            from_username: from_user,
            to_username: to_user,
            amount,
        },
    )
    .await
    .context("failed to create transfer attestation")?;

    let flow = connect_and_run_flow(verifier_addr, server_addr, &server_name, transfer.tx_id)
        .await
        .context("failed to run STWO attestation proof flow")?;

    ensure!(
        flow.inputs.tx_id == transfer.tx_id,
        "tx_id mismatch: TLSN extracted {} but transfer created {}",
        flow.inputs.tx_id,
        transfer.tx_id
    );

    ensure!(
        flow.verification.success,
        "verifier rejected STWO proof: {}",
        flow.verification.message
    );

    info!(
        tx_id = flow.inputs.tx_id,
        to_user_id = flow.inputs.to_user_id,
        amount = flow.inputs.amount,
        signed_ticket = flow.verification.signed_ticket.is_some(),
        "TLSN -> STWO proof flow finished successfully"
    );

    Ok(())
}

async fn connect_and_run_flow(
    verifier_addr: SocketAddr,
    server_addr: SocketAddr,
    server_name: &str,
    tx_id: u64,
) -> Result<attestation_proof_stwo::StwoAttestationProofFlow> {
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
        .connect(verifier_addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;

    run_stwo_attestation_proof_flow(
        tokio::io::join(recv, send),
        server_addr,
        server_name,
        tx_id,
    )
    .await
}
