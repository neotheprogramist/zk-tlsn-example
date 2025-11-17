use thiserror::Error;

#[derive(Error, Debug)]
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
}
