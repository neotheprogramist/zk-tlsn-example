mod attestation;
mod error;
mod flow;
pub mod parser;
pub mod prover;
pub mod transport;

#[cfg(not(target_arch = "wasm32"))]
mod verifier;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use attestation::{
    AMOUNT_WIDTH, ATTESTATION_LEN, FiatTransferAttestation, TX_ID_WIDTH, USER_ID_WIDTH,
    encode_transfer_attestation, parse_transfer_attestation,
};
pub use error::{Error, Result, TranscriptError};
pub use flow::{
    MAX_RECV_DATA, MAX_SENT_DATA, transfer_request, transfer_request_reveal,
    transfer_response_reveal, transfer_tls_configs,
};
pub use prover::{BodyFieldConfig, KeyValueCommitConfig, Prover, ProverOutput, RevealConfig};
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
#[cfg(not(target_arch = "wasm32"))]
pub use verifier::{Verifier, VerifierOutput};
