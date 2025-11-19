use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("Invalid syntax: {0}")]
    InvalidSyntax(String),

    #[error("Unexpected rule: {0}")]
    UnexpectedRule(String),

    #[error("Missing field: {0}")]
    MissingField(String),
}

pub type Result<T> = std::result::Result<T, ParseError>;
