pub mod error;
pub mod prover;
pub mod verifier;

pub use error::Error;
pub use prover::{
    BodyFieldConfig, KeyValueCommitConfig, Prover, ProverBuilder, ProverOutput, RevealConfig,
};
pub use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    hash::HashAlgId,
    transcript::{
        Direction, PartialTranscript, TranscriptCommitment, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
    webpki::{CertificateDer, RootCertStore},
};
pub use verifier::{
    ExpectedValue, FieldAssertion, Validator, ValidatorBuilder, Verifier, VerifierBuilder,
    VerifierOutput,
};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
