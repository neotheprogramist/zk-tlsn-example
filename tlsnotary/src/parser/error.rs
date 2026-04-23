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

impl<R: pest::RuleType> From<pest::error::Error<R>> for ParseError {
    fn from(err: pest::error::Error<R>) -> Self {
        Self::InvalidSyntax(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;
