use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error(transparent)]
    Parser(#[from] parser::ParseError),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid transcript data: {0}")]
    InvalidTranscript(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

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
