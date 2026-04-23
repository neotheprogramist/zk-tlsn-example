use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol message frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[error("missing required notarization field: {0}")]
    MissingField(&'static str),

    #[error(transparent)]
    InvalidProvingRequest(#[from] ProvingRequestError),

    #[error(transparent)]
    InvalidConfig(#[from] ConfigError),

    #[error("verification session timed out after {timeout_secs} seconds")]
    SessionTimeout { timeout_secs: u64 },

    #[error("invalid transcript range for {label}: {start}..{end} exceeds transcript length {len}")]
    InvalidTranscriptRange {
        label: String,
        start: usize,
        end: usize,
        len: usize,
    },

    #[error(transparent)]
    Parse(#[from] tlsnotary::parser::ParseError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    TlsNotary(#[from] tlsnotary::Error),

    #[error(transparent)]
    Tlsn(#[from] tlsn::Error),

    #[error(transparent)]
    TlsnVerifierConfig(#[from] tlsn::config::verifier::VerifierConfigError),

    #[error(transparent)]
    TlsConfig(#[from] crate::error::TlsConfigError),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("max_sent_data {actual} exceeds limit {limit}")]
    MaxSentDataTooLarge { limit: usize, actual: usize },

    #[error("max_recv_data {actual} exceeds limit {limit}")]
    MaxRecvDataTooLarge { limit: usize, actual: usize },

    #[error("expected MPC-TLS protocol")]
    UnsupportedProtocol,
}

#[derive(Debug, Error)]
pub enum ProvingRequestError {
    #[error("missing required server identity reveal")]
    MissingServerIdentity,

    #[error("missing required transcript reveal payload")]
    MissingRevealPayload,
}
