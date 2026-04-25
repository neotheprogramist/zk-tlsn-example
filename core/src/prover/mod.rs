mod builder;
mod reveal;

use std::sync::Arc;

pub use builder::ProverBuilder;
use futures::{AsyncRead, AsyncWrite, channel::oneshot, join};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
pub use reveal::{BodyFieldConfig, KeyValueCommitConfig, RevealConfig};
use reveal::{reveal_request, reveal_response};
use tlsn::{
    Session, SessionHandle,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::TlsCommitConfig,
    },
    hash::HashAlgId,
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
};

use crate::{
    Error,
    transport::{FuturesIo, Runtime},
};

#[derive(Debug, Clone)]
pub struct ProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub transcript_secrets: Vec<tlsn::transcript::TranscriptSecret>,
    pub response_body: Vec<u8>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub struct Prover {
    runtime: Arc<dyn Runtime>,
    tls_client_config: TlsClientConfig,
    tls_commit_config: TlsCommitConfig,
    request: Request<Empty<Bytes>>,
    request_reveal_config: RevealConfig,
    response_reveal_config: RevealConfig,
    hash_alg: HashAlgId,
}

impl Prover {
    #[must_use]
    pub fn builder(
        runtime: Arc<dyn Runtime>,
        tls_client_config: TlsClientConfig,
        tls_commit_config: TlsCommitConfig,
        request: Request<Empty<Bytes>>,
    ) -> ProverBuilder {
        ProverBuilder {
            runtime,
            tls_client_config,
            tls_commit_config,
            request,
            request_reveal_config: RevealConfig::default(),
            response_reveal_config: RevealConfig::default(),
            hash_alg: HashAlgId::BLAKE3,
        }
    }

    pub async fn prove<T, S>(
        self,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<(T, ProverOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mpc_tls_connection, prover_fut, session_handle, verifier_io_rx) =
            Self::setup_and_connect(
                self.runtime,
                self.tls_client_config,
                self.tls_commit_config,
                verifier_socket,
                server_socket,
            )
            .await?;

        let (mut prover, response_body) =
            Self::execute_http_exchange(mpc_tls_connection, prover_fut, self.request).await?;

        let prove_config = Self::build_prove_config(
            &mut prover,
            self.hash_alg,
            &self.request_reveal_config,
            &self.response_reveal_config,
        )?;

        let sent = prover.transcript().sent().to_owned();
        let received = prover.transcript().received().to_owned();
        let prover_output = Self::generate_and_finalize_proof(prover, &prove_config).await?;

        session_handle.close();
        let verifier_io = verifier_io_rx
            .await
            .map_err(|_| Error::SessionDriverCancelled)
            .and_then(|inner| inner)?;

        Ok((
            verifier_io,
            ProverOutput {
                sent,
                received,
                transcript_commitments: prover_output.transcript_commitments,
                transcript_secrets: prover_output.transcript_secrets,
                response_body,
            },
        ))
    }

    async fn setup_and_connect<T, S>(
        runtime: Arc<dyn Runtime>,
        tls_client_config: TlsClientConfig,
        tls_commit_config: TlsCommitConfig,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<
        (
            impl AsyncRead + AsyncWrite + Send + Unpin,
            impl std::future::Future<
                Output = std::result::Result<
                    tlsn::prover::Prover<tlsn::prover::state::Committed>,
                    tlsn::Error,
                >,
            > + Send,
            SessionHandle,
            oneshot::Receiver<Result<T, Error>>,
        ),
        Error,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut session = Session::new(verifier_socket);
        let prover = session.new_prover(ProverConfig::builder().build()?)?;
        let (driver, handle) = session.split();
        let (verifier_io_tx, verifier_io_rx) = oneshot::channel();
        runtime.spawn_detached(Box::pin(async move {
            let outcome = driver.await.map_err(Error::from);
            let _ = verifier_io_tx.send(outcome);
        }));

        let prover = prover.commit(tls_commit_config).await?;
        let (connection, prover_future) = prover.connect(tls_client_config, server_socket).await?;
        Ok((connection, prover_future, handle, verifier_io_rx))
    }

    async fn execute_http_exchange<C>(
        mpc_tls_connection: C,
        prover_fut: impl std::future::Future<
            Output = std::result::Result<
                tlsn::prover::Prover<tlsn::prover::state::Committed>,
                tlsn::Error,
            >,
        > + Send,
        request: Request<Empty<Bytes>>,
    ) -> Result<
        (
            tlsn::prover::Prover<tlsn::prover::state::Committed>,
            Vec<u8>,
        ),
        Error,
    >
    where
        C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mpc_tls_connection = FuturesIo::new(mpc_tls_connection);
        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

        let request_task = async move {
            let response = request_sender.send_request(request).await?;
            let status = response.status();

            if status != StatusCode::OK {
                return Err(Error::HttpRequestFailed(status.as_u16()));
            }

            Ok::<Vec<u8>, Error>(response.collect().await?.to_bytes().to_vec())
        };

        let (prover, connection_result, request_task_result) =
            join!(prover_fut, connection, request_task);

        Ok((prover?, {
            connection_result?;
            request_task_result?
        }))
    }

    fn build_prove_config(
        prover: &mut tlsn::prover::Prover<tlsn::prover::state::Committed>,
        hash_alg: HashAlgId,
        request_reveal_config: &RevealConfig,
        response_reveal_config: &RevealConfig,
    ) -> Result<ProveConfig, Error> {
        let transcript = prover.transcript();
        let mut prove_config_builder = ProveConfig::builder(transcript);
        prove_config_builder.server_identity();

        let mut transcript_commitment_builder = TranscriptCommitConfig::builder(transcript);
        transcript_commitment_builder
            .default_kind(TranscriptCommitmentKind::Hash { alg: hash_alg });

        reveal_request(
            transcript.sent(),
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            request_reveal_config,
        )?;

        reveal_response(
            transcript.received(),
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            response_reveal_config,
        )?;

        prove_config_builder.transcript_commit(transcript_commitment_builder.build()?);
        Ok(prove_config_builder.build()?)
    }

    async fn generate_and_finalize_proof(
        mut prover: tlsn::prover::Prover<tlsn::prover::state::Committed>,
        prove_config: &ProveConfig,
    ) -> Result<tlsn::prover::ProverOutput, Error> {
        let prover_output = prover.prove(prove_config).await?;
        prover.close().await?;
        Ok(prover_output)
    }
}

// `Prover`'s Rust-facing API is generic over `AsyncRead + AsyncWrite` sockets.
// `wasm-bindgen` can't export generic methods, so the `wasm` module
// monomorphizes `prove::<WebTransportIo, WebTransportIo>` into a concrete
// JS-callable entry point. All TLS/request config construction is driven from
// a single JSON payload to keep the boundary small.
#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::sync::Arc;

    use http_body_util::Empty;
    use hyper::{Method, Request, body::Bytes};
    use serde::{Deserialize, Serialize};
    use thiserror::Error;
    use tlsn::{
        config::{
            tls::TlsConfigError,
            tls_commit::{TlsCommitConfigError, mpc::MpcTlsConfigError},
        },
        connection::{DnsName, InvalidDnsNameError},
    };
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::WebTransportBidirectionalStream;

    use super::{Prover, RevealConfig};
    use crate::{
        CertificateDer, HashAlgId, MpcTlsConfig, RootCertStore, ServerName, TlsClientConfig,
        TlsCommitConfig,
        transport::{WasmRuntime, WebTransportIo},
    };

    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
    }

    /// Must be awaited once, from the Flow 1 Worker, before constructing the
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
        TlsClientConfig(#[from] TlsConfigError),
        #[error("mpc tls config: {0}")]
        MpcTlsConfig(#[from] MpcTlsConfigError),
        #[error("tls commit config: {0}")]
        TlsCommitConfig(#[from] TlsCommitConfigError),
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

    #[wasm_bindgen]
    impl Prover {
        /// JS constructor: accepts a JSON blob of `JsProverInputs` and builds
        /// a `Prover` with the wasm runtime. Rust callers should use
        /// `Prover::builder(...)` instead.
        #[wasm_bindgen(constructor)]
        pub fn new(inputs_json: &str) -> Result<Prover, JsError> {
            Ok(Self::from_js_inputs(inputs_json)?)
        }

        /// Concrete monomorphization of `prove::<WebTransportIo, _>` for the
        /// browser. Takes two `WebTransportBidirectionalStream` handles from
        /// JS, wraps them as `WebTransportIo`, and delegates to the generic
        /// `prove` method.
        pub async fn prove_streams(
            self,
            verifier_stream: WebTransportBidirectionalStream,
            server_stream: WebTransportBidirectionalStream,
        ) -> Result<JsValue, JsError> {
            let verifier_io = WebTransportIo::from_bidi(verifier_stream)?;
            let server_io = WebTransportIo::from_bidi(server_stream)?;
            let (_verifier_io, output) = self.prove(verifier_io, server_io).await?;
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

    impl Prover {
        fn from_js_inputs(inputs_json: &str) -> Result<Prover, JsBoundaryError> {
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

            Ok(Prover::builder(
                Arc::new(WasmRuntime),
                tls_client_config,
                tls_commit_config,
                request,
            )
            .request_reveal_config(inputs.request_reveal)
            .response_reveal_config(inputs.response_reveal)
            .hash_alg(hash_alg)
            .build())
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::{JsHttpRequest, JsProverInputs, JsProverOutput, initialize, start};
