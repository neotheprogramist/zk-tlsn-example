use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Certificate generation failed: {0}")]
    Generation(#[from] rcgen::Error),

    #[error("Invalid date/time: {0}")]
    InvalidDateTime(String),

    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
}

#[derive(Error, Debug)]
pub enum TlsConfigError {
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    #[error("PEM parsing failed: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),

    #[error("PEM decode failed: {0}")]
    PemDecode(#[from] pem::PemError),

    #[error("TLS error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum QuicConfigError {
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    PemDecode(#[from] pem::PemError),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),

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
