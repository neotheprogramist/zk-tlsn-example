use thiserror::Error;
use zktlsn_core::Error as CoreError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid JsProverInputs JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verifier outcome frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
}
