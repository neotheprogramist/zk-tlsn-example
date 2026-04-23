use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};

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
    zktlsn::ensure_cli_toolchain().context("failed to validate nargo/bb CLI toolchain")?;
    zktlsn::compile_attestation_package().context("failed to compile the attestation circuit")?;
    Ok(())
}
