use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use demo::{
    init_logging,
    ledger::{self, AppConfig, AppState, DemoServerConfig, TransferRequest},
    service::{self, ServiceConfig},
    tls::get_or_create_cert_bytes,
};
use tokio::net::lookup_host;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(
    name = "zktlsn",
    about = "zk-tlsn demo: HTTPS ledger + browser WASM service"
)]
struct Cli {
    #[arg(long, env = "ZKTLSN_SERVER_LISTEN_ADDR", default_value = "[::]:8443")]
    server_listen_addr: SocketAddr,
    #[arg(
        long,
        env = "ZKTLSN_SERVER_CERT_PATH",
        default_value = ".data/server/cert.pem"
    )]
    server_cert_path: PathBuf,
    #[arg(
        long,
        env = "ZKTLSN_SERVER_KEY_PATH",
        default_value = ".data/server/key.pem"
    )]
    server_key_path: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVICE_LISTEN_ADDR", default_value = "[::]:8444")]
    service_listen_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVICE_CERT_DIR", default_value = ".data/service")]
    service_cert_dir: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVICE_ASSET_DIR", default_value = "demo/assets")]
    service_asset_dir: PathBuf,
    #[arg(
        long,
        env = "ZKTLSN_SERVICE_TEMPLATE_DIR",
        default_value = "demo/templates"
    )]
    service_template_dir: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVER_ADDR", default_value = "localhost:8443")]
    server_addr: String,
    #[arg(long, env = "ZKTLSN_SERVER_NAME", default_value = "localhost")]
    server_name: String,
    #[arg(long, env = "ZKTLSN_FROM_USER", default_value = "alice")]
    from_user: String,
    #[arg(long, env = "ZKTLSN_TO_USER", default_value = "treasury")]
    to_user: String,
    #[arg(long, env = "ZKTLSN_TRANSFER_AMOUNT", default_value_t = 25)]
    transfer_amount: u64,
}

fn main() {
    init_logging().expect("failed to initialize logging");
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to construct multi-thread tokio runtime");
    if let Err(err) = runtime.block_on(run(cli)) {
        error!(error = %format!("{err:#}"), "zktlsn.run.failed");
        std::process::exit(1);
    }
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

    let state = AppState::new(AppConfig::demo_defaults())
        .context("failed to initialise demo ledger state")?;

    let transfer = ledger::seed_transfer(
        &state,
        TransferRequest {
            from_username: cli.from_user.clone(),
            to_username: cli.to_user.clone(),
            amount: cli.transfer_amount,
        },
    )
    .await
    .context("failed to seed initial demo transfer")?;
    info!(
        tx_id = transfer.tx_id,
        from = %transfer.from_username,
        to = %transfer.to_username,
        amount = transfer.amount,
        "demo.transfer.seeded"
    );

    let server_cert_der = get_or_create_cert_bytes(&cli.server_cert_path, &cli.server_key_path)
        .context("failed to prepare server certificate")?;
    let server_cert_der_hex = hex::encode(&server_cert_der);

    let server_cfg = DemoServerConfig {
        listen_addr: cli.server_listen_addr,
        cert_path: cli.server_cert_path.clone(),
        key_path: cli.server_key_path,
    };
    let service_cfg = ServiceConfig {
        listen_addr: cli.service_listen_addr,
        cert_dir: cli.service_cert_dir,
        asset_dir: cli.service_asset_dir,
        template_dir: cli.service_template_dir,
        allowed_target,
        server_host: server_host.to_string(),
        server_name: cli.server_name,
        server_cert_der_hex,
        from_user: cli.from_user,
        to_user: cli.to_user,
        transfer_amount: cli.transfer_amount,
        tx_id: transfer.tx_id,
    };

    let server_task = tokio::spawn(ledger::serve(server_cfg, state));
    let service_task = tokio::spawn(async move {
        service::serve(service_cfg)
            .await
            .map_err(anyhow::Error::from)
    });

    tokio::select! {
        result = server_task => result.context("ledger task panicked")?.context("ledger flow failed"),
        result = service_task => result.context("service task panicked")?.context("service flow failed"),
    }
}
