pub mod attestation;
pub mod connect;
pub mod ledger;
pub mod service;
pub mod tls;
pub mod transfer_verifier;

use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use thiserror::Error;
use tracing_subscriber::{
    EnvFilter,
    fmt::{format::FmtSpan, time::UtcTime},
};

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
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(filter))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_timer(UtcTime::rfc_3339())
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .with_level(true)
        .with_ansi(false)
        .with_span_events(FmtSpan::NONE)
        .compact()
        .try_init()?;
    Ok(())
}
