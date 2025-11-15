use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkTlsNotaryError {
    #[error("Prover setup failed: {0}")]
    ProverSetup(String),

    #[error("Prover connection failed: {0}")]
    ProverConnection(String),

    #[error("MPC-TLS handshake failed: {0}")]
    MpcTlsHandshake(String),

    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error("Prover prove phase failed: {0}")]
    ProveFailed(String),

    #[error("Verifier verification failed: {0}")]
    VerifyFailed(String),

    #[error("Parser error: {0}")]
    Parser(#[from] parser::ParserError),

    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Invalid transcript data: {0}")]
    InvalidTranscript(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error(transparent)]
    TlsnProver(#[from] tlsn::prover::ProverError),

    #[error(transparent)]
    TlsnVerifier(#[from] tlsn::verifier::VerifierError),

    #[error(transparent)]
    TlsnProtocolConfigBuilder(#[from] tlsn::config::ProtocolConfigBuilderError),

    #[error(transparent)]
    TlsnProveConfigBuilderBuilder(#[from] tlsn::prover::ProveConfigBuilderError),

    #[error(transparent)]
    TlsnTranscriptCommitConfigBuilder(#[from] tlsn::transcript::TranscriptCommitConfigBuilderError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}
