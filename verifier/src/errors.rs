use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol message frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[error("missing required notarization field: {0}")]
    MissingField(&'static str),

    #[error("invalid protocol configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid proving request: {0}")]
    InvalidProvingRequest(String),

    #[error("commitment binding failed: {0}")]
    CommitmentBindingFailed(String),

    #[error("no commitments found for binding")]
    NoCommitmentsFound,

    #[error("proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("request parsing failed: {0}")]
    RequestParse(String),

    #[error("response parsing failed: {0}")]
    ResponseParse(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    TlsNotary(#[from] tlsnotary::Error),
}
