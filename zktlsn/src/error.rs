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

    #[error("Verification key mismatch")]
    VerificationKeyMismatch,

    #[error("Committed hash does not match proof")]
    CommittedHashMismatch,

    #[error("Proof is invalid")]
    InvalidProof,

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

    #[error("missing required configuration: {0}")]
    MissingConfig(&'static str),

    #[error("Invalid commitment length: expected {expected} bytes, got {actual} bytes")]
    InvalidCommitmentLength { expected: usize, actual: usize },

    #[error("invalid ticket private key hex")]
    TicketKeyHex(#[from] hex::FromHexError),

    #[error("ticket private key must be 32 bytes, got {actual}")]
    TicketKeyLength { actual: usize },

    #[error(transparent)]
    TicketSigningKey(#[from] k256::ecdsa::Error),

    #[error("ticket public key missing {0} coordinate")]
    TicketPublicKeyCoordinate(&'static str),

    #[error("ticket signature must be 64 bytes, got {actual}")]
    TicketSignatureLength { actual: usize },
}

pub type Result<T> = std::result::Result<T, ZkTlsnError>;
