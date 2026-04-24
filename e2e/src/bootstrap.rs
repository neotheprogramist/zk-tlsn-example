use std::future::Future;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use tracing::error;

static LOGGING_INIT: OnceLock<Result<(), String>> = OnceLock::new();

pub fn init_logging() -> Result<()> {
    let stored = LOGGING_INIT.get_or_init(|| {
        match crate::logging::init_logging("info").context("failed to initialize logging") {
            Ok(()) => Ok(()),
            Err(err) => Err(format!("{err:#}")),
        }
    });
    match stored.as_ref() {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!("{err}")),
    }
}

pub fn ensure_attestation_toolchain() -> Result<()> {
    zktlsn::cli::ensure_cli_toolchain().context("failed to validate nargo/bb CLI toolchain")?;
    zktlsn::recursive::compile_attestation_package()
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
