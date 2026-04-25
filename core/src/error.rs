use thiserror::Error;
use tlsn::{hash::HashAlgId, transcript::Direction};

use crate::parser::ParseError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    // ---- Attestation encoding ----
    #[error("invalid attestation length: expected {expected} bytes, got {actual}")]
    AttestationLength { expected: usize, actual: usize },

    #[error("missing attestation segment: {0}")]
    AttestationSegmentMissing(&'static str),

    #[error("invalid attestation segment {label}")]
    AttestationSegmentInvalid {
        label: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("attestation segment {label} value {value} exceeds {width}-digit limit")]
    AttestationSegmentTooWide {
        label: &'static str,
        value: u64,
        width: u32,
    },

    // ---- HTTP parsing / transcript ----
    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error(transparent)]
    Parser(#[from] ParseError),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error(transparent)]
    InvalidTranscript(#[from] TranscriptError),

    #[error("{context}: {details}")]
    InvalidInput {
        context: &'static str,
        details: String,
    },

    // ---- TLSN session driver ----
    #[error("tlsn session driver was cancelled before it could return the socket")]
    SessionDriverCancelled,

    #[error("{context} policy rejected verifier session: {reason}")]
    PolicyRejected {
        context: &'static str,
        reason: String,
    },

    // ---- tlsn upstream errors ----
    #[error(transparent)]
    Tlsn(#[from] tlsn::Error),

    #[error(transparent)]
    TlsnProveConfig(#[from] tlsn::config::prove::ProveConfigError),

    #[error(transparent)]
    TlsnTranscriptCommitConfigBuilder(#[from] tlsn::transcript::TranscriptCommitConfigBuilderError),

    #[error(transparent)]
    TlsnTlsConfig(#[from] tlsn::config::tls::TlsConfigError),

    #[error(transparent)]
    TlsnTlsCommitConfig(#[from] tlsn::config::tls_commit::TlsCommitConfigError),

    #[error(transparent)]
    TlsnMpcTlsConfig(#[from] tlsn::config::tls_commit::mpc::MpcTlsConfigError),

    #[error(transparent)]
    TlsnProverConfig(#[from] tlsn::config::prover::ProverConfigError),

    #[error(transparent)]
    TlsnVerifierConfig(#[from] tlsn::config::verifier::VerifierConfigError),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    // ---- stdlib boundary ----
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Utf8Str(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    // ---- ZK commitment checks ----
    #[error("no received commitments found in transcript")]
    NoReceivedCommitments,

    #[error("no received secrets found in transcript")]
    NoReceivedSecrets,

    #[error("invalid commitment direction, expected Received")]
    InvalidCommitmentDirection,

    #[error("invalid hash algorithm, expected BLAKE3")]
    InvalidHashAlgorithm,

    #[error("hash verification failed: computed hash does not match committed hash")]
    HashVerificationFailed,

    // ---- nargo/bb tool pipeline ----
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

    #[error("cached Barretenberg SRS not found at {path}. Run the fixture binary first.")]
    MissingCachedSrs { path: String },

    #[error(
        "cached Barretenberg SRS at {path} is invalid or stale. Rerun the fixture binary to refresh it."
    )]
    InvalidCachedSrs { path: String },
}

#[derive(Error, Debug)]
pub enum TranscriptError {
    #[error("expected server name '{expected}', got '{actual}'")]
    ServerName { expected: String, actual: String },

    #[error("expected {expected:?} hash algorithm in {direction:?} direction, got {actual:?}")]
    HashAlgorithm {
        expected: HashAlgId,
        actual: HashAlgId,
        direction: Direction,
    },

    #[error("missing {ctx} header '{key}'")]
    MissingHeader { ctx: &'static str, key: String },

    #[error("{ctx} header '{key}' has no value")]
    HeaderWithoutValue { ctx: &'static str, key: String },

    #[error("missing {ctx} body field '{key}'")]
    MissingBodyField { ctx: &'static str, key: String },

    #[error("missing value for {ctx} field '{key}'")]
    MissingFieldValue { ctx: &'static str, key: String },

    #[error("{ctx} header '{key}': expected '{expected}', got '{actual}'")]
    HeaderMismatch {
        ctx: &'static str,
        key: String,
        expected: String,
        actual: String,
    },

    #[error("{ctx} field '{key}': expected {expected}, got {actual}")]
    FieldMismatch {
        ctx: &'static str,
        key: String,
        expected: String,
        actual: String,
    },
}
