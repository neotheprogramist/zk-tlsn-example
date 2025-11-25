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
