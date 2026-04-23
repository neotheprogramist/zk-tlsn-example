use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use crate::error::LoggingError;

pub fn init_logging(filter: &str) -> Result<(), LoggingError> {
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

pub fn init_test_logging() -> Result<(), LoggingError> {
    let filter = EnvFilter::try_new("info")?;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
        .with_test_writer()
        .try_init();
    Ok(())
}
