use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use e2e::bootstrap;
use e2e::demo::{DemoConnectionConfig, create_transfer};
use e2e::server::app::TransferRequest;
use e2e::service::{ServiceConfig, serve};
use e2e::tls::load_test_cert_bytes;
use tokio::net::lookup_host;
use tracing::info;

#[derive(Debug, Parser)]
struct Cli {
    /// Listen address for both TCP/HTTPS (static assets, pages) and
    /// QUIC/WebTransport (`/verifier/connect`, `/proxy/connect`).
    #[arg(long, env = "ZKTLSN_SERVICE_LISTEN_ADDR")]
    listen_addr: SocketAddr,

    /// Directory where the service's 14-day ECDSA P-256 self-signed cert is
    /// cached (`cert.pem` + `key.pem`).
    #[arg(long, env = "ZKTLSN_SERVICE_CERT_DIR", default_value = ".data/service")]
    cert_dir: PathBuf,

    /// Directory containing `index.html` template assets: JS driver, CSS,
    /// and the wasm-bindgen output under `wasm/`.
    #[arg(long, env = "ZKTLSN_SERVICE_ASSET_DIR", default_value = "e2e/assets")]
    asset_dir: PathBuf,

    /// Askama template directory (holds `index.html`).
    #[arg(
        long,
        env = "ZKTLSN_SERVICE_TEMPLATE_DIR",
        default_value = "e2e/templates"
    )]
    template_dir: PathBuf,

    /// Demo ledger address; the only `host:port` the `/proxy/connect`
    /// endpoint will tunnel TCP to. Must match what the `server` binary is
    /// listening on (`ZKTLSN_SERVER_ADDR`).
    #[arg(long, env = "ZKTLSN_SERVER_ADDR")]
    server_addr: String,

    /// DNS name presented by the demo ledger's TLS cert (SNI + cert SAN).
    /// Used by the browser-side MPC-TLS client config.
    #[arg(long, env = "ZKTLSN_SERVER_NAME", default_value = "localhost")]
    server_name: String,

    /// Path to the demo ledger's TLS certificate (PEM). The hex-encoded DER
    /// is embedded in the prover page so JS can pass it to `new Prover(...)`.
    #[arg(long, env = "ZKTLSN_SERVER_CERT_PATH")]
    server_cert_path: PathBuf,

    /// Transfer sender (ledger username).
    #[arg(long, env = "ZKTLSN_FROM_USER", default_value = "alice")]
    from_user: String,

    /// Transfer recipient (ledger username).
    #[arg(long, env = "ZKTLSN_TO_USER", default_value = "treasury")]
    to_user: String,

    /// Transfer amount.
    #[arg(long, env = "ZKTLSN_TRANSFER_AMOUNT", default_value_t = 25)]
    transfer_amount: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    bootstrap::run_main("service", || run(Cli::parse())).await;
}

async fn run(cli: Cli) -> Result<()> {
    let (server_host, server_port) = cli
        .server_addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("ZKTLSN_SERVER_ADDR `{}` is not host:port", cli.server_addr))?;
    let server_port: u16 = server_port
        .parse()
        .context("invalid port in ZKTLSN_SERVER_ADDR")?;

    let allowed_target = lookup_host((server_host, server_port))
        .await
        .context("failed to resolve ZKTLSN_SERVER_ADDR")?
        .next()
        .ok_or_else(|| anyhow!("failed to resolve {}", cli.server_addr))?;

    let server_cert_der =
        load_test_cert_bytes(&cli.server_cert_path).context("failed to load server certificate")?;
    let server_cert_der_hex = hex::encode(&server_cert_der);

    let demo = DemoConnectionConfig {
        server_addr: allowed_target,
        server_name: cli.server_name.clone(),
        server_cert_path: cli.server_cert_path.clone(),
    };
    let transfer = create_transfer(
        &demo,
        &TransferRequest {
            from_username: cli.from_user.clone(),
            to_username: cli.to_user.clone(),
            amount: cli.transfer_amount,
        },
    )
    .await
    .context("failed to create demo transfer")?;
    info!(
        tx_id = transfer.tx_id,
        from = %transfer.from_username,
        to = %transfer.to_username,
        amount = transfer.amount,
        "service: created demo transfer via demo ledger"
    );

    serve(ServiceConfig {
        listen_addr: cli.listen_addr,
        cert_dir: cli.cert_dir,
        asset_dir: cli.asset_dir,
        template_dir: cli.template_dir,
        allowed_target,
        server_host: server_host.to_string(),
        server_name: cli.server_name,
        server_cert_der_hex,
        from_user: cli.from_user,
        to_user: cli.to_user,
        transfer_amount: cli.transfer_amount,
        tx_id: transfer.tx_id,
    })
    .await
    .context("failed to run service")?;
    Ok(())
}
