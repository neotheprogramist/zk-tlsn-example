mod attestation;
mod error;
pub mod parser;
pub mod prover;
pub mod transport;

#[cfg(not(target_arch = "wasm32"))]
mod verifier;
#[cfg(not(target_arch = "wasm32"))]
pub mod zk;

pub use attestation::{
    AMOUNT_WIDTH, ATTESTATION_LEN, FiatTransferAttestation, TX_ID_WIDTH, USER_ID_WIDTH,
    encode_transfer_attestation, parse_transfer_attestation,
};
pub use error::{Error, Result, TranscriptError};
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
        Direction, PartialTranscript, Transcript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
    webpki::{CertificateDer, RootCertStore},
};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::SmolRuntime;
#[cfg(target_arch = "wasm32")]
pub use transport::{WasmRuntime, WebTransportIo};
#[cfg(not(target_arch = "wasm32"))]
pub use verifier::{
    ExpectedValue, FieldAssertion, Validator, ValidatorBuilder, Verifier, VerifierOutput,
};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn repo_root() -> &'static std::path::Path {
    // PROOF: CARGO_MANIFEST_DIR is set by Cargo at compile time and always
    // points to this crate's Cargo.toml directory, which by workspace layout
    // is a child of the workspace root.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core crate lives under the workspace root")
}
