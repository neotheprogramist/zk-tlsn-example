use thiserror::Error;
use tlsn::{hash::HashAlgId, transcript::Direction};

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error(transparent)]
    Parser(#[from] crate::parser::ParseError),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error(transparent)]
    InvalidTranscript(#[from] TranscriptError),

    #[error("builder is missing required field: {0}")]
    MissingBuilderField(&'static str),

    #[error("{context}: {details}")]
    InvalidInput {
        context: &'static str,
        details: String,
    },

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
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::InvalidTranscript(TranscriptError::InvalidUtf8(err))
    }
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

    #[error(transparent)]
    InvalidUtf8(#[from] std::str::Utf8Error),
}
