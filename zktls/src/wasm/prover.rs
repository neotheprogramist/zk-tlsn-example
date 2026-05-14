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
    pub commitment_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum VerificationOutcome {
    #[serde(rename = "success")]
    Success {},
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
        let js_output = JsProverOutput {
            sent: output.sent,
            received: output.received,
            response_body: output.response_body,
            commitment_count: output.transcript_commitments.len(),
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
        hash_alg: HashAlgId::BLAKE3,
    })
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
    let VerificationOutcome::Success {} = serde_json::from_slice(&payload)?;
    Ok(())
}
