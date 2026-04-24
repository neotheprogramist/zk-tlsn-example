use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkTlsnError {
    #[error("No received commitments found in transcript")]
    NoReceivedCommitments,

    #[error("No received secrets found in transcript")]
    NoReceivedSecrets,

    #[error("Invalid commitment direction, expected Received")]
    InvalidCommitmentDirection,

    #[error("Invalid hash algorithm, expected BLAKE3")]
    InvalidHashAlgorithm,

    #[error("Hash verification failed: computed hash does not match committed hash")]
    HashVerificationFailed,

    #[error(transparent)]
    JsonParseError(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Attestation(#[from] shared::AttestationError),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("required CLI tool `{tool}` is not installed or not on PATH")]
    MissingTool { tool: String },

    #[error("unsupported {tool} version: expected `{expected}`, got `{actual}`")]
    UnsupportedToolVersion {
        tool: String,
        expected: String,
        actual: String,
    },

    #[error(
        "command failed: `{program} {args}` ({status}) stderr: {stderr}",
        args = .args.join(" ")
    )]
    CommandFailed {
        program: String,
        args: Vec<String>,
        status: String,
        stderr: String,
    },

    #[error(
        "Cached Barretenberg SRS not found at {path}. Run `cargo run --package zktlsn --release --example fixture` first."
    )]
    MissingCachedSrs { path: String },

    #[error(
        "Cached Barretenberg SRS at {path} is invalid or stale. Rerun `cargo run --package zktlsn --release --example fixture` to refresh it."
    )]
    InvalidCachedSrs { path: String },

    #[error("{context}: {details}")]
    InvalidInput {
        context: &'static str,
        details: String,
    },
}

pub type Result<T> = std::result::Result<T, ZkTlsnError>;
