pub mod error;
pub mod prover;
pub mod verifier;

pub use error::Error;
pub use prover::{
    BodyFieldConfig, KeyValueCommitConfig, Prover, ProverBuilder, ProverOutput, RevealConfig,
};
pub use tlsn::{
    config::{CertificateDer, ProtocolConfig, ProtocolConfigValidator, RootCertStore},
    connection::ServerName,
    hash::HashAlgId,
    prover::{ProverConfig, TlsConfig},
    transcript::{
        Direction, PartialTranscript, TranscriptCommitment, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
    verifier::VerifierConfig,
};
pub use verifier::{
    ExpectedValue, FieldAssertion, Validator, ValidatorBuilder, Verifier, VerifierBuilder,
    VerifierOutput,
};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
