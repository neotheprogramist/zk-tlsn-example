mod error;
pub mod parser;
pub mod policy;
mod prover;
mod reveal;
pub mod transport;

mod verifier;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::{Error, Result};
pub use prover::{Prover, ProverConfigBundle, ProverOutput};
pub use reveal::{BodyFieldConfig, KeyValueCommitConfig, RevealConfig};
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
        Direction, PartialTranscript, Transcript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
    webpki::{CertificateDer, RootCertStore},
};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::SmolRuntime;
pub use verifier::{Verifier, VerifierConfigBundle, VerifierOutput};
