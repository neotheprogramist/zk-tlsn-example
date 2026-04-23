use std::{net::SocketAddr, path::Path};

use clap::Parser;
use e2e::bootstrap;
use e2e::testing::{TestQuicConfig, get_or_create_test_quic_config};
use e2e::verifier::serve;
use quinn::Endpoint;
use tracing::error;

type ExampleResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
    bootstrap::init_logging().expect("failed to initialize logging");

    if let Err(err) = run(Cli::parse()).await {
        error!(error = %err, "Verifier example failed");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> ExampleResult<()> {
    let TestQuicConfig { server_config, .. } =
        get_or_create_test_quic_config(Path::new(&cli.cert_path), Path::new(&cli.key_path)).await?;

    let endpoint = Endpoint::server(server_config, cli.listen_addr)?;
    tracing::info!("Reliable streams server listening on {}", cli.listen_addr);
    serve(endpoint).await;
    Ok(())
}
