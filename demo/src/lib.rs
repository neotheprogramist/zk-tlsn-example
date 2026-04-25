pub mod browser;
pub mod ledger;
pub mod settlement;
pub mod tls;
pub mod transport;

use std::{future::Future, net::SocketAddr, path::PathBuf, sync::OnceLock};

use alloy::primitives::Address;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use thiserror::Error;
use tracing::error;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

// ─── CLI argument groups ───────────────────────────────────────────────────

#[derive(Debug, Clone, Args)]
pub struct TlsnClientCli {
    #[arg(long, env = "ZKTLSN_SERVER_ADDR")]
    pub server_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVER_NAME")]
    pub server_name: String,
    #[arg(long, env = "ZKTLSN_SERVER_CERT_PATH")]
    pub server_cert_path: PathBuf,
    #[arg(long, env = "ZKTLSN_VERIFIER_ADDR")]
    pub verifier_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_VERIFIER_CERT_PATH")]
    pub verifier_cert_path: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct ChainCli {
    #[arg(long, env = "ZKTLSN_ANVIL_RPC_URL")]
    pub anvil_rpc_url: String,
    #[arg(long, env = "ZKTLSN_ANVIL_PRIVATE_KEY")]
    pub anvil_private_key: String,
    #[arg(long, env = "ZKTLSN_MINT_RECIPIENT")]
    pub mint_recipient: Address,
}

#[derive(Debug, Clone, Args)]
pub struct CommonCli {
    #[command(flatten)]
    pub tlsn: TlsnClientCli,
    #[command(flatten)]
    pub chain: ChainCli,
}

// ─── Bootstrap: logging + toolchain ───────────────────────────────────────

static LOGGING_INIT: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("invalid log filter")]
    Filter(#[from] tracing_subscriber::filter::ParseError),

    #[error(transparent)]
    Init(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub fn init_logging() -> Result<()> {
    let stored = LOGGING_INIT.get_or_init(|| match try_init_logging("info") {
        Ok(()) => Ok(()),
        Err(err) => Err(format!("{err:#}")),
    });
    match stored.as_ref() {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!("{err}")),
    }
}

fn try_init_logging(filter: &str) -> Result<(), LoggingError> {
    let filter = EnvFilter::try_new(filter)?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
        .try_init()?;
    Ok(())
}

pub fn ensure_attestation_toolchain() -> Result<()> {
    zktlsn_core::zk::cli::ensure_cli_toolchain()
        .context("failed to validate nargo/bb CLI toolchain")?;
    zktlsn_core::zk::recursive::compile_attestation_package()
        .context("failed to compile the attestation circuit")?;
    Ok(())
}

pub async fn run_main<F, Fut>(name: &'static str, f: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    init_logging().expect("failed to initialize logging");
    if let Err(err) = f().await {
        error!(error = %format!("{err:#}"), "{name} flow failed");
        std::process::exit(1);
    }
}
