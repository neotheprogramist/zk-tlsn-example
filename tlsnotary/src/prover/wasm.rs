#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use http_body_util::Empty;
use hyper::{Method, Request, body::Bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use web_sys::WebTransportBidirectionalStream;

use tlsn::connection::{DnsName, InvalidDnsNameError};
use wasm_bindgen_futures::JsFuture;

use crate::{
    CertificateDer, HashAlgId, MpcTlsConfig, Prover, RevealConfig, RootCertStore, ServerName,
    TlsClientConfig, TlsCommitConfig, io::WebTransportIo, runtime::WasmRuntime,
};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Must be awaited once, from the Flow 3 Worker, before constructing the
/// first `Prover`. Starts the `web-spawn` spawner worker that tlsn's MPC
/// parallelism dispatches onto.
#[wasm_bindgen]
pub async fn initialize() -> Result<(), JsError> {
    JsFuture::from(web_spawn::start_spawner())
        .await
        .map_err(|err| JsError::new(&format!("web-spawn spawner failed to start: {err:?}")))?;
    Ok(())
}

#[derive(Debug, Error)]
enum JsBoundaryError {
    #[error("invalid JsProverInputs JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid server_name: {0}")]
    DnsName(#[from] InvalidDnsNameError),
    #[error("invalid HTTP method: {0}")]
    HttpMethod(#[from] hyper::http::method::InvalidMethod),
    #[error("failed to build HTTP request: {0}")]
    HttpBuild(#[from] hyper::http::Error),
    #[error("tls client config: {0}")]
    TlsClientConfig(#[from] tlsn::config::tls::TlsConfigError),
    #[error("mpc tls config: {0}")]
    MpcTlsConfig(#[from] tlsn::config::tls_commit::mpc::MpcTlsConfigError),
    #[error("tls commit config: {0}")]
    TlsCommitConfig(#[from] tlsn::config::tls_commit::TlsCommitConfigError),
    #[error("unsupported hash_alg `{0}` (expected `blake3`, `sha256`, or `keccak256`)")]
    UnsupportedHashAlg(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsProverInputs {
    pub server_name: String,
    pub server_cert_der: Vec<u8>,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub request: JsHttpRequest,
    pub request_reveal: RevealConfig,
    pub response_reveal: RevealConfig,
    pub hash_alg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsHttpRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize)]
pub struct JsProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub response_body: Vec<u8>,
    pub commitment_count: usize,
}

#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    inner: Prover,
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(inputs_json: &str) -> Result<JsProver, JsError> {
        Ok(Self::build(inputs_json)?)
    }

    pub async fn prove(
        self,
        verifier_stream: WebTransportBidirectionalStream,
        server_stream: WebTransportBidirectionalStream,
    ) -> Result<JsValue, JsError> {
        let verifier_io = WebTransportIo::from_bidi(verifier_stream)?;
        let server_io = WebTransportIo::from_bidi(server_stream)?;
        let (_verifier_io, output) = self.inner.prove(verifier_io, server_io).await?;
        let commitment_count = output.transcript_commitments.len();
        let js_output = JsProverOutput {
            sent: output.sent,
            received: output.received,
            response_body: output.response_body,
            commitment_count,
        };
        let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(js_output.serialize(&serializer)?)
    }
}

impl JsProver {
    fn build(inputs_json: &str) -> Result<JsProver, JsBoundaryError> {
        let inputs: JsProverInputs = serde_json::from_str(inputs_json)?;

        let dns_name = DnsName::try_from(inputs.server_name.as_str())?;
        let root_store = RootCertStore {
            roots: vec![CertificateDer(inputs.server_cert_der)],
        };

        let tls_client_config = TlsClientConfig::builder()
            .server_name(ServerName::Dns(dns_name))
            .root_store(root_store)
            .build()?;

        let mpc_config = MpcTlsConfig::builder()
            .max_sent_data(inputs.max_sent_data)
            .max_recv_data(inputs.max_recv_data)
            .build()?;
        let tls_commit_config = TlsCommitConfig::builder().protocol(mpc_config).build()?;

        let method = Method::from_bytes(inputs.request.method.as_bytes())?;
        let mut request_builder = Request::builder().method(method).uri(&inputs.request.uri);
        for (name, value) in &inputs.request.headers {
            request_builder = request_builder.header(name, value);
        }
        let request = request_builder.body(Empty::<Bytes>::new())?;

        let hash_alg = match inputs.hash_alg.as_str() {
            "blake3" => HashAlgId::BLAKE3,
            "sha256" => HashAlgId::SHA256,
            "keccak256" => HashAlgId::KECCAK256,
            other => return Err(JsBoundaryError::UnsupportedHashAlg(other.to_string())),
        };

        let inner = Prover::builder(
            Arc::new(WasmRuntime),
            tls_client_config,
            tls_commit_config,
            request,
        )
        .request_reveal_config(inputs.request_reveal)
        .response_reveal_config(inputs.response_reveal)
        .hash_alg(hash_alg)
        .build();

        Ok(JsProver { inner })
    }
}
