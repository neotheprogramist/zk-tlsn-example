use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use clap::Parser;
use e2e::bootstrap;
use e2e::tls::{TestQuicConfig, get_or_create_test_quic_config};
use e2e::verifier::serve;
use quinn::Endpoint;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, env = "ZKTLSN_VERIFIER_ADDR")]
    listen_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_QUIC_CERT_PATH")]
    cert_path: String,
    #[arg(long, env = "ZKTLSN_QUIC_KEY_PATH")]
    key_path: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    bootstrap::run_main("verifier", || run(Cli::parse())).await;
}

async fn run(cli: Cli) -> Result<()> {
    let TestQuicConfig { server_config, .. } =
        get_or_create_test_quic_config(Path::new(&cli.cert_path), Path::new(&cli.key_path))
            .await
            .context("failed to load QUIC server config")?;

    let endpoint =
        Endpoint::server(server_config, cli.listen_addr).context("failed to bind QUIC endpoint")?;
    tracing::info!("Reliable streams server listening on {}", cli.listen_addr);
    serve(endpoint).await;
    Ok(())
}
