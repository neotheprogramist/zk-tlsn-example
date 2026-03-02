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
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, TlsCommitProtocolConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    hash::HashAlgId,
    transcript::{
        Direction, PartialTranscript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret,
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
