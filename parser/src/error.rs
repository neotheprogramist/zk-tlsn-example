use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Failed to parse HTTP request")]
    RequestParseFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to parse HTTP response")]
    ResponseParseFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

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

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ParseBool(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    ParseFloat(#[from] std::num::ParseFloatError),
}
