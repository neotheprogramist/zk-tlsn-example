use thiserror::Error;

use crate::parser::ParseError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error(transparent)]
    Parser(#[from] ParseError),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid DNS server name: {0}")]
    InvalidDnsName(String),

    #[error(transparent)]
    RequestBuild(#[from] hyper::http::Error),

    #[error("reveal rule '{rule}' did not match any {target} in {direction}")]
    RevealRuleNotMatched {
        direction: &'static str,
        target: &'static str,
        rule: String,
    },

    #[error("reveal rule '{rule}' expected a {expected} body field, got a {actual}")]
    RevealStructureMismatch {
        rule: String,
        expected: &'static str,
        actual: &'static str,
    },

    #[error("tlsn session driver was cancelled before it could return the socket")]
    SessionDriverCancelled,

    #[error("{context} policy rejected verifier session: {reason}")]
    PolicyRejected {
        context: &'static str,
        reason: String,
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
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Utf8Str(#[from] std::str::Utf8Error),

    #[cfg(target_arch = "wasm32")]
    #[error("invalid wasm input JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(target_arch = "wasm32")]
    #[error("verifier outcome frame too large: {0} bytes")]
    FrameTooLarge(usize),
}
