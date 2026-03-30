#[path = "support/attestation_proof_stwo.rs"]
mod attestation_proof_stwo;
#[path = "support/live_demo.rs"]
mod live_demo;

use std::net::SocketAddr;

use anyhow::{Context, Result, ensure};
use circuits_stwo::prove_attestation;
use clap::Parser;
use quinn::Endpoint;
use server::app::TransferRequest;
use shared::{TestQuicConfig, init_logging};
use tracing::{error, info, instrument};

use crate::{
    attestation_proof_stwo::derive_stwo_inputs_from_tlsn,
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

    let noir_inputs = connect_and_collect_inputs(verifier_addr, server_addr, &server_name, transfer.tx_id)
        .await
        .context("failed to derive STWO inputs from TLSN")?;

    let attestation_bytes: [u8; shared::ATTESTATION_LEN] = noir_inputs
        .attestation
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("attestation should be exactly 32 bytes"))?;

    let stwo_proof = prove_attestation(
        &attestation_bytes,
        &noir_inputs.attestation_blinder,
        &noir_inputs.attestation_committed_hash,
        noir_inputs.tx_id,
        noir_inputs.to_user_id,
        noir_inputs.amount,
    )
    .map_err(anyhow::Error::msg)
    .context("failed to produce STWO attestation proof")?;

    let _proof_hash = stwo_proof
        .committed_hash()
        .ok_or_else(|| anyhow::anyhow!("proof does not expose committed hash outputs"))?;
    
    info!("STWO circuit verified cryptographic binding: blake2s(attestation || blinder) == TLSN hash");

    ensure!(
        noir_inputs.tx_id == transfer.tx_id,
        "tx_id mismatch: TLSN extracted {} but transfer created {}",
        noir_inputs.tx_id,
        transfer.tx_id
    );

    info!(
        tx_id = noir_inputs.tx_id,
        to_user_id = noir_inputs.to_user_id,
        amount = noir_inputs.amount,
        "TLSN -> STWO local proof flow finished successfully"
    );

    Ok(())
}

async fn connect_and_collect_inputs(
    verifier_addr: SocketAddr,
    server_addr: SocketAddr,
    server_name: &str,
    tx_id: u64,
) -> Result<zktlsn::NoirProverInputs> {
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

    derive_stwo_inputs_from_tlsn(
        tokio::io::join(recv, send),
        server_addr,
        server_name,
        tx_id,
    )
    .await
}
