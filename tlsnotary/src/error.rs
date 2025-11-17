use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error(transparent)]
    Parser(#[from] parser::ParserError),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid transcript data: {0}")]
    InvalidTranscript(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error(transparent)]
    TlsnProver(#[from] tlsn::prover::ProverError),

    #[error(transparent)]
    TlsnVerifier(#[from] tlsn::verifier::VerifierError),

    #[error(transparent)]
    TlsnProtocolConfigBuilder(#[from] tlsn::config::ProtocolConfigBuilderError),

    #[error(transparent)]
    TlsnProveConfigBuilder(#[from] tlsn::prover::ProveConfigBuilderError),

    #[error(transparent)]
    TlsnTranscriptCommitConfigBuilder(#[from] tlsn::transcript::TranscriptCommitConfigBuilderError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}
