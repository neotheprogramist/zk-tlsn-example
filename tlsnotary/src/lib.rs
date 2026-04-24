pub mod error;
pub(crate) mod io;
pub mod parser;
pub mod prover;
pub(crate) mod runtime;

#[cfg(not(target_arch = "wasm32"))]
pub mod verifier;

pub use error::Error;
pub use prover::{BodyFieldConfig, KeyValueCommitConfig, Prover, ProverOutput, RevealConfig};
pub use runtime::Runtime;
#[cfg(not(target_arch = "wasm32"))]
pub use runtime::SmolRuntime;
#[cfg(target_arch = "wasm32")]
pub use runtime::WasmRuntime;
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
pub use verifier::{
    ExpectedValue, FieldAssertion, Validator, ValidatorBuilder, Verifier, VerifierOutput,
};

pub type Result<T> = std::result::Result<T, Error>;
