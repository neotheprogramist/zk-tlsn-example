use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use clap::Parser;
use server::{
    app::{AppConfig, InitialUser, get_app},
    handle_connection,
};
use smol::net::TcpListener;
use tracing::error;

#[derive(Debug, Clone, Parser)]
struct Cli {
    #[arg(
        long,
        env = "ZKTLSN_SERVER_LISTEN_ADDR",
        default_value = "127.0.0.1:8443"
    )]
    listen_addr: SocketAddr,
    #[arg(
        long = "user",
        env = "ZKTLSN_SERVER_USERS",
        value_delimiter = ',',
        default_values = ["alice=100", "bob=40", "treasury=0"]
    )]
    users: Vec<String>,
    #[arg(long, env = "ZKTLSN_SERVER_SPECIAL_USER", default_value = "treasury")]
    special_user: String,
}

fn main() {
    shared::init_logging("info");

    smol::block_on(async {
        if let Err(err) = run(Cli::parse()).await {
            error!(error = %err, "TLS server example failed");
            std::process::exit(1);
        }
    });
}

async fn run(cli: Cli) -> Result<()> {
    let listen_addr = cli.listen_addr;
    let cert_path = Path::new("test_cert.pem");
    let key_path = Path::new("test_key.pem");
    let test_tls_config = shared::get_or_create_test_tls_config(cert_path, key_path)
        .context("failed to load TLS test configuration")?;
    let app = get_app(app_config(&cli)?).context("failed to build server app")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;

    tracing::info!(listen_addr = %listen_addr, "TLS server listening");

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("failed to accept connection")?;
        let app = app.clone();
        let server_config = test_tls_config.server_config.clone();

        tracing::info!(%addr, "Accepted connection");
        smol::spawn(async move {
            if let Err(error) = handle_connection(app, server_config, stream).await {
                tracing::error!(error = %error, "Connection error");
            }
        })
        .detach();
    }
}

fn app_config(cli: &Cli) -> Result<AppConfig> {
    cli.users
        .iter()
        .cloned()
        .map(parse_user)
        .collect::<Result<Vec<_>>>()
        .map(|users| AppConfig {
            users,
            special_username: cli.special_user.clone(),
        })
}

fn parse_user(value: String) -> Result<InitialUser> {
    value
        .split_once('=')
        .context("user must be formatted as <username>=<balance>")
        .and_then(|(username, balance)| {
            balance
                .parse::<u64>()
                .with_context(|| format!("invalid balance for user '{username}'"))
                .map(|parsed_balance| InitialUser::new(username, parsed_balance))
        })
}
