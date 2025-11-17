pub mod error;
pub mod prover;
pub mod transcript;
pub mod verifier;

pub use error::Error;
pub use prover::{Prover, ProverBuilder, ProverOutput, RevealConfig};
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
pub use transcript::{extract_received_commitments, extract_received_secrets};
pub use verifier::{Verifier, VerifierBuilder, VerifierOutput};

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
