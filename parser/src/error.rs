use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Failed to parse HTTP request: {0}")]
    RequestParseFailed(String),

    #[error("Failed to parse HTTP response: {0}")]
    ResponseParseFailed(String),

    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Invalid header format")]
    InvalidHeader,

    #[error("Invalid value format")]
    InvalidValue,

    #[error("Header not found: {0}")]
    HeaderNotFound(String),

    #[error("Keypath not found: {0}")]
    KeypathNotFound(String),
}
