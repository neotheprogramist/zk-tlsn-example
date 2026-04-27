pub mod connect;
pub mod ledger;
pub mod service;
pub mod tls;

use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use thiserror::Error;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

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
