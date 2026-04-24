use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsFixtureError {
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    #[error(transparent)]
    PemDecode(#[from] pem::PemError),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("invalid log filter")]
    Filter(#[from] tracing_subscriber::filter::ParseError),

    #[error(transparent)]
    Init(#[from] Box<dyn std::error::Error + Send + Sync>),
}
