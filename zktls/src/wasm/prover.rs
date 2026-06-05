use std::sync::Arc;

use futures::AsyncReadExt;
use http_body_util::Empty;
use hyper::{Method, Request as HttpRequest, body::Bytes};
use serde::{Deserialize, Serialize};
use tlsn::{
    config::{
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
    },
    connection::{DnsName, ServerName},
    hash::HashAlgId,
    transcript::{
        Direction, TranscriptCommitment, TranscriptSecret, hash::PlaintextHashSecret,
    },
    webpki::{CertificateDer, RootCertStore},
};
use wasm_bindgen::prelude::*;
use web_sys::WebTransportBidirectionalStream;

use super::{WasmRuntime, io::WebTransportIo};
use crate::{
    Error,
    prover::{Prover as CoreProver, ProverConfigBundle},
    reveal::RevealConfig,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsProverInputs {
    pub server_name: String,
    pub server_cert_der: Vec<u8>,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub request_method: String,
    pub request_uri: String,
    pub request_headers: Vec<(String, String)>,
    pub request_reveal_config: RevealConfig,
    pub response_reveal_config: RevealConfig,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub response_body: Vec<u8>,
    /// Convenience count for callers that only care about the size of
    /// the commitments list (the existing `/zktls` UI displays this).
    pub commitment_count: usize,
    /// One entry per TLSN transcript-hash commitment, in the order the
    /// prover emitted them. The JS caller picks the commitment matching
    /// its expected (direction, alg, range) and uses `hash_bytes` as the
    /// public commitment input to the in-circuit opening proof, plus
    /// `blinder_bytes` and the plaintext slice of `sent`/`received` as
    /// private witness.
    pub commitments: Vec<JsTranscriptCommitment>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsTranscriptCommitment {
    /// `"sent"` or `"received"` — which transcript half the committed
    /// bytes live in.
    pub direction: &'static str,
    /// Contiguous byte ranges (half-open) within the transcript half.
    /// For the vault flow we only commit a single field, so this is one
    /// entry; the wire format keeps the list shape for forward-compat.
    pub ranges: Vec<JsCommitmentRange>,
    /// Raw [`HashAlgId`] byte. Poseidon2 = 4; the JS caller filters on
    /// this so other commitments (e.g. headers) don't get fed into the
    /// vault opening circuit.
    pub alg: u8,
    /// Commitment hash bytes (32 bytes for Poseidon2-M31).
    pub hash_bytes: Vec<u8>,
    /// Blinder bytes (16 bytes). Private witness on the vault side, not
    /// disclosed to the verifier outside the prover.
    pub blinder_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsCommitmentRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum VerificationOutcome {
    #[serde(rename = "success")]
    Success {},
    /// Verifier accepted the MPC-TLS session but rejected the policy check
    /// applied to the resulting transcript. The reason string is surfaced
    /// back to the JS caller via [`Error::VerifierPolicyRejected`].
    #[serde(rename = "failure")]
    Failure { reason: String },
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Prover(CoreProver);

#[wasm_bindgen]
impl Prover {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn prove_streams(
        &self,
        inputs_json: &str,
        verifier_stream: WebTransportBidirectionalStream,
        server_stream: WebTransportBidirectionalStream,
    ) -> Result<JsValue, JsError> {
        let config = build_prover_config(inputs_json)?;
        let verifier_io = WebTransportIo::from_bidi(verifier_stream)?;
        let server_io = WebTransportIo::from_bidi(server_stream)?;
        let (mut verifier_io, output) = self.0.prove(config, verifier_io, server_io).await?;
        read_verification_outcome(&mut verifier_io).await?;
        let commitments = pair_commitments_with_secrets(
            &output.transcript_commitments,
            &output.transcript_secrets,
        );
        let js_output = JsProverOutput {
            sent: output.sent,
            received: output.received,
            response_body: output.response_body,
            commitment_count: commitments.len(),
            commitments,
        };
        let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(js_output.serialize(&serializer)?)
    }
}

fn build_prover_config(inputs_json: &str) -> Result<ProverConfigBundle, Error> {
    let inputs: JsProverInputs = serde_json::from_str(inputs_json)?;
    let dns = DnsName::try_from(inputs.server_name.as_str())
        .map_err(|err| Error::InvalidDnsName(format!("{err}")))?;
    let tls_client_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(dns))
        .root_store(RootCertStore {
            roots: vec![CertificateDer(inputs.server_cert_der)],
        })
        .build()?;
    let mpc_config = MpcTlsConfig::builder()
        .max_sent_data(inputs.max_sent_data)
        .max_recv_data(inputs.max_recv_data)
        .build()?;
    let tls_commit_config = TlsCommitConfig::builder().protocol(mpc_config).build()?;

    let method =
        Method::from_bytes(inputs.request_method.as_bytes()).map_err(hyper::http::Error::from)?;
    let mut builder = HttpRequest::builder()
        .method(method)
        .uri(inputs.request_uri);
    for (name, value) in inputs.request_headers {
        builder = builder.header(name, value);
    }
    let request = builder.body(Empty::<Bytes>::new())?;

    Ok(ProverConfigBundle {
        runtime: Arc::new(WasmRuntime),
        tls_client_config,
        tls_commit_config,
        request,
        request_reveal_config: inputs.request_reveal_config,
        response_reveal_config: inputs.response_reveal_config,
        hash_alg: HashAlgId::POSEIDON2,
    })
}

/// Zip the prover's `transcript_commitments` and `transcript_secrets`
/// into the JS-serializable shape. TLSN emits both lists in the same
/// order; we match a secret to its commitment by `(direction, idx,
/// alg)` to stay robust if that invariant ever changes. Commitments
/// without a matching secret are skipped — the JS opener has no way to
/// use them.
fn pair_commitments_with_secrets(
    commitments: &[TranscriptCommitment],
    secrets: &[TranscriptSecret],
) -> Vec<JsTranscriptCommitment> {
    commitments
        .iter()
        .filter_map(|commitment| {
            let TranscriptCommitment::Hash(plaintext_hash) = commitment else {
                return None;
            };
            let secret = secrets.iter().find_map(|s| {
                let TranscriptSecret::Hash(s) = s else {
                    return None;
                };
                (s.direction == plaintext_hash.direction
                    && s.idx == plaintext_hash.idx
                    && s.alg == plaintext_hash.hash.alg)
                    .then_some(s)
            })?;
            Some(plaintext_hash_to_js(plaintext_hash, secret))
        })
        .collect()
}

fn plaintext_hash_to_js(
    hash: &tlsn::transcript::hash::PlaintextHash,
    secret: &PlaintextHashSecret,
) -> JsTranscriptCommitment {
    let ranges = hash
        .idx
        .iter()
        .map(|range| JsCommitmentRange {
            start: range.start,
            end: range.end,
        })
        .collect();
    JsTranscriptCommitment {
        direction: direction_label(hash.direction),
        ranges,
        alg: hash.hash.alg.as_u8(),
        hash_bytes: hash.hash.value.as_bytes().to_vec(),
        blinder_bytes: secret.blinder.as_bytes().to_vec(),
    }
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Sent => "sent",
        Direction::Received => "received",
    }
}

async fn read_verification_outcome(io: &mut WebTransportIo) -> Result<(), Error> {
    const MAX_FRAME_BYTES: usize = 1 << 20;

    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    match serde_json::from_slice::<VerificationOutcome>(&payload)? {
        VerificationOutcome::Success {} => Ok(()),
        VerificationOutcome::Failure { reason } => Err(Error::VerifierPolicyRejected(reason)),
    }
}
