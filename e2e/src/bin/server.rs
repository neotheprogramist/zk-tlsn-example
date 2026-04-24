use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

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
    bootstrap::run_main("server", || run(Cli::parse())).await;
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
