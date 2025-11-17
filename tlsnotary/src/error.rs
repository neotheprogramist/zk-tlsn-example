use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("prover setup failed: {0}")]
    ProverSetup(String),

    #[error("prover connection failed: {0}")]
    ProverConnection(String),

    #[error("MPC-TLS handshake failed: {0}")]
    MpcTlsHandshake(String),

    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error("prover prove phase failed: {0}")]
    ProveFailed(String),

    #[error("verifier verification failed: {0}")]
    VerifyFailed(String),

    #[error("parser error: {0}")]
    Parser(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid transcript data: {0}")]
    InvalidTranscript(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("TLSN prover error: {0}")]
    TlsnProver(String),

    #[error("TLSN verifier error: {0}")]
    TlsnVerifier(String),

    #[error("TLSN protocol config builder error: {0}")]
    TlsnProtocolConfigBuilder(String),

    #[error("TLSN prove config builder error: {0}")]
    TlsnProveConfigBuilder(String),

    #[error("TLSN transcript commit config builder error: {0}")]
    TlsnTranscriptCommitConfigBuilder(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Hyper error: {0}")]
    Hyper(String),
}

impl From<parser::ParserError> for Error {
    fn from(err: parser::ParserError) -> Self {
        Self::Parser(err.to_string())
    }
}

impl From<tlsn::prover::ProverError> for Error {
    fn from(err: tlsn::prover::ProverError) -> Self {
        Self::TlsnProver(err.to_string())
    }
}

impl From<tlsn::verifier::VerifierError> for Error {
    fn from(err: tlsn::verifier::VerifierError) -> Self {
        Self::TlsnVerifier(err.to_string())
    }
}

impl From<tlsn::config::ProtocolConfigBuilderError> for Error {
    fn from(err: tlsn::config::ProtocolConfigBuilderError) -> Self {
        Self::TlsnProtocolConfigBuilder(err.to_string())
    }
}

impl From<tlsn::prover::ProveConfigBuilderError> for Error {
    fn from(err: tlsn::prover::ProveConfigBuilderError) -> Self {
        Self::TlsnProveConfigBuilder(err.to_string())
    }
}

impl From<tlsn::transcript::TranscriptCommitConfigBuilderError> for Error {
    fn from(err: tlsn::transcript::TranscriptCommitConfigBuilderError) -> Self {
        Self::TlsnTranscriptCommitConfigBuilder(err.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Self::Hyper(err.to_string())
    }
}
