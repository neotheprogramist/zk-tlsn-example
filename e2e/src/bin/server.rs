use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use tracing::error;

use e2e::{
    bootstrap,
    server::{DemoServerConfig, serve},
};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, env = "ZKTLSN_SERVER_LISTEN_ADDR")]
    listen_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVER_CERT_PATH")]
    cert_path: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVER_KEY_PATH")]
    key_path: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    bootstrap::init_logging().expect("failed to initialize logging");

    if let Err(err) = run(Cli::parse()).await {
        error!(error = %err, "TLS server example failed");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    serve(DemoServerConfig {
        listen_addr: cli.listen_addr,
        cert_path: cli.cert_path,
        key_path: cli.key_path,
    })
    .await
    .context("failed to run e2e server")
}
