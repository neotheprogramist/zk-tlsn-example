use thiserror::Error;

#[derive(Error, Debug)]
pub enum SharedError {
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    #[error("TLS configuration error: {0}")]
    TlsConfig(#[from] TlsConfigError),

    #[error("QUIC configuration error: {0}")]
    QuicConfig(#[from] QuicConfigError),
}

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

    #[error("PEM parse error for {path}: {details}")]
    PemParse { path: String, details: String },

    #[error("invalid QUIC TLS configuration: {0}")]
    InvalidConfig(String),
}
