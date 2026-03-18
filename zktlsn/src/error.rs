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

    #[error("Circuit bytecode not found in program.json")]
    BytecodeNotFound,

    #[error(transparent)]
    JsonParseError(#[from] serde_json::Error),

    #[error("Verification key mismatch")]
    VerificationKeyMismatch,

    #[error("Committed hash does not match proof")]
    CommittedHashMismatch,

    #[error("Proof is invalid")]
    InvalidProof,

    #[error("Noir error: {0}")]
    NoirError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

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

    #[error(
        "Balance too large: balance length {balance_length} + prefix {prefix_length} + suffix {suffix_length} exceeds total length {total_length}"
    )]
    BalanceTooLarge {
        balance_length: usize,
        total_length: usize,
        prefix_length: usize,
        suffix_length: usize,
    },

    #[error("Invalid balance format: {0}")]
    InvalidBalanceFormat(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid commitment length: expected {expected} bytes, got {actual} bytes")]
    InvalidCommitmentLength { expected: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, ZkTlsnError>;
