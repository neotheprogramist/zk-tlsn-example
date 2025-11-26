use axum::response::IntoResponse;
use hyper::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error("Failed to connect to prover: {0}")]
    Connection(String),

    #[error("Invalid request from prover: {0}")]
    BadProverRequest(String),

    #[error("Unauthorized request from prover: {0}")]
    UnauthorizedProverRequest(String),
}

impl IntoResponse for NotaryServerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) => (
                StatusCode::UNAUTHORIZED,
                unauthorized_request_error.to_string(),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid session phase: expected Verification, got {0}")]
    InvalidSessionPhase(String),

    #[error("Failed to parse response: {0}")]
    ResponseParseError(String),

    #[error("No commitments found for binding")]
    NoCommitmentsFound,

    #[error("ZK proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Commitment binding failed: {0}")]
    CommitmentBindingFailed(String),
}

impl IntoResponse for VerificationError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            VerificationError::SessionNotFound(_) => StatusCode::NOT_FOUND,
            VerificationError::InvalidSessionPhase(_) => StatusCode::BAD_REQUEST,
            VerificationError::ResponseParseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VerificationError::NoCommitmentsFound => StatusCode::BAD_REQUEST,
            VerificationError::ProofVerificationFailed(_) => StatusCode::BAD_REQUEST,
            VerificationError::CommitmentBindingFailed(_) => StatusCode::BAD_REQUEST,
        };

        (status, self.to_string()).into_response()
    }
}
