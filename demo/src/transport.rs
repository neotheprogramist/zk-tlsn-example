use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use async_compat::Compat;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request, body::Bytes};
use hyper_util::rt::TokioIo;
use quinn::Endpoint;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::{io::join, net::TcpStream};
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};
use zktlsn_core::{
    ATTESTATION_LEN, BodyFieldConfig, CertificateDer, Error as ProverError, KeyValueCommitConfig,
    MpcTlsConfig, Prover, RevealConfig, RootCertStore, ServerName as TlsnServerName, SmolRuntime,
    TlsClientConfig, TlsCommitConfig, TlsCommitProtocolConfig, TranscriptCommitment,
    TranscriptSecret, Verifier, VerifierConfig, VerifierOutput,
};

use crate::{
    ledger::{ServerConfigResponse, TransferRequest, TransferResponse},
    tls::{TestTlsConfig, get_or_create_test_tls_config, load_test_client_tls_config},
};

// ─── Limits & timeouts ─────────────────────────────────────────────────────

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_FRAME_BYTES: usize = 1 << 20;

// ─── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol message frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    TlsNotary(#[from] zktlsn_core::Error),

    #[error(transparent)]
    TlsnVerifierConfig(#[from] tlsn::config::verifier::VerifierConfigError),

    #[error(transparent)]
    TlsConfig(#[from] crate::tls::TlsFixtureError),
}

#[derive(Debug, Error)]
enum HandlerError {
    #[error("failed to accept connection: {0}")]
    Accept(#[from] quinn::ConnectionError),
}

// ─── Verification outcome (verifier → prover wire format) ──────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum VerificationOutcome {
    #[serde(rename = "success")]
    Success {
        server_name: String,
        commitment_count: usize,
        message: String,
    },
    #[serde(rename = "failure")]
    Failure {
        server_name: String,
        message: String,
    },
}

impl VerificationOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    pub fn server_name(&self) -> &str {
        match self {
            Self::Success { server_name, .. } | Self::Failure { server_name, .. } => server_name,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Success { message, .. } | Self::Failure { message, .. } => message,
        }
    }

    pub async fn read_from<IO>(io: &mut IO) -> Result<Self, ProtocolError>
    where
        IO: AsyncRead + Unpin + Send,
    {
        read_json_frame(io).await
    }

    pub async fn write_to<IO>(&self, io: &mut IO) -> Result<(), ProtocolError>
    where
        IO: AsyncWrite + Unpin + Send,
    {
        write_json_frame(io, self).await
    }
}

// ─── Verifier side ─────────────────────────────────────────────────────────

pub async fn serve(endpoint: Endpoint) {
    info!("Verifier service ready, waiting for QUIC connections");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = handle(incoming).await {
                error!(error = %error, "Connection task failed");
            }
        });
    }
}

async fn handle(incoming: quinn::Incoming) -> Result<(), HandlerError> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    info!(%remote_addr, "Accepted QUIC connection");

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(error) => return Err(error.into()),
        };

        let stream_id = send.id();
        let stream = join(recv, send);
        tokio::spawn(async move {
            info!(%stream_id, "Starting notarize pipeline on stream");
            match tokio::time::timeout(SESSION_TIMEOUT, run_notarize_stream(stream)).await {
                Ok(Ok(())) => info!(%stream_id, "Pipeline completed"),
                Ok(Err(error)) => error!(%stream_id, error = %error, "Pipeline failed"),
                Err(_) => warn!(
                    %stream_id,
                    timeout_secs = SESSION_TIMEOUT.as_secs(),
                    "Session timed out"
                ),
            }
        });
    }

    info!(%remote_addr, "Connection closed");
    Ok(())
}

pub async fn run_notarize_stream<IO>(stream: IO) -> Result<(), ProtocolError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut io, output) = Verifier::new(create_verifier_config()?)
        .verify(
            Compat::new(stream),
            |protocol| protocol_policy(protocol).map_err(String::from),
            |server_identity, reveal_present| {
                reveal_policy(server_identity, reveal_present).map_err(String::from)
            },
        )
        .await?;

    log_verifier_output(&output);
    let outcome = VerificationOutcome::Success {
        server_name: output.server_name.clone(),
        commitment_count: output.transcript_commitments.len(),
        message: "Attestation-only flow completed".into(),
    };
    info!(success = true, "Sending verification outcome");
    outcome.write_to(&mut io).await?;
    io.close().await?;
    Ok(())
}

fn create_verifier_config() -> Result<VerifierConfig, ProtocolError> {
    let TestTlsConfig { cert_bytes, .. } = get_or_create_test_tls_config(
        Path::new(".data/tls/server-cert.pem"),
        Path::new(".data/tls/server-key.pem"),
    )?;

    Ok(VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()?)
}

fn protocol_policy(protocol: &TlsCommitProtocolConfig) -> Result<(), &'static str> {
    let TlsCommitProtocolConfig::Mpc(mpc) = protocol else {
        return Err("expected MPC-TLS protocol");
    };
    if mpc.max_sent_data() > MAX_SENT_DATA {
        return Err("max_sent_data exceeds limit");
    }
    if mpc.max_recv_data() > MAX_RECV_DATA {
        return Err("max_recv_data exceeds limit");
    }
    Ok(())
}

fn reveal_policy(
    server_identity_revealed: bool,
    reveal_payload_present: bool,
) -> Result<(), &'static str> {
    if !server_identity_revealed {
        return Err("missing required server identity reveal");
    }
    if !reveal_payload_present {
        return Err("missing required transcript reveal payload");
    }
    Ok(())
}

fn log_verifier_output(output: &VerifierOutput) {
    info!(
        server_name = %output.server_name,
        sent_len = output.transcript.sent_unsafe().len(),
        received_len = output.transcript.received_unsafe().len(),
        commitment_count = output.transcript_commitments.len(),
        parsed_request = ?output.parsed_request,
        parsed_response = ?output.parsed_response,
        "Received notarization transcript from prover"
    );
}

async fn read_json_frame<IO, T>(io: &mut IO) -> Result<T, ProtocolError>
where
    IO: AsyncRead + Unpin + Send,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(frame_len));
    }
    let mut payload = vec![0u8; frame_len];
    io.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

async fn write_json_frame<IO, T>(io: &mut IO, value: &T) -> Result<(), ProtocolError>
where
    IO: AsyncWrite + Unpin + Send,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let len =
        u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(&payload).await?;
    io.flush().await?;
    Ok(())
}

// ─── Prover side ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DemoConnectionConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub server_cert_path: PathBuf,
}

pub struct NotarizedFlow {
    pub verification: VerificationOutcome,
    pub commitment_count: usize,
    pub transcript_commitments: Vec<TranscriptCommitment>,
    pub transcript_secrets: Vec<TranscriptSecret>,
    pub received_transcript: Vec<u8>,
}

pub async fn open_client_endpoint(verifier_cert_path: &Path) -> Result<Endpoint> {
    let client_config = crate::tls::load_test_quic_client_config(verifier_cert_path)
        .await
        .context("failed to load QUIC client configuration")?;
    let mut endpoint = Endpoint::client("[::]:0".parse().context("invalid client bind address")?)
        .context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

pub async fn connect_and_attest(
    endpoint: &Endpoint,
    verifier_addr: SocketAddr,
    server_addr: SocketAddr,
    server_name: &str,
    server_cert_path: &Path,
    tx_id: u64,
) -> Result<NotarizedFlow> {
    let connection = endpoint
        .connect(verifier_addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;
    run_attest_only_flow(
        tokio::io::join(recv, send),
        server_addr,
        server_name,
        server_cert_path,
        tx_id,
    )
    .await
}

async fn run_attest_only_flow<IO>(
    stream: IO,
    server_addr: SocketAddr,
    server_name: &str,
    server_cert_path: &Path,
    tx_id: u64,
) -> Result<NotarizedFlow>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let cert_bytes = crate::tls::load_test_cert_bytes(server_cert_path)
        .context("failed to load TLS server certificate")?;
    let (tls_client_config, tls_commit_config) = create_prover_config(cert_bytes, server_name)
        .context("failed to create prover TLS configuration")?;

    let prover = Prover::builder(
        Arc::new(SmolRuntime),
        tls_client_config,
        tls_commit_config,
        create_tlsn_request(tx_id).context("failed to build attestation request")?,
    )
    .request_reveal_config(create_request_reveal_config())
    .response_reveal_config(create_response_reveal_config())
    .build();

    let verifier_io = Compat::new(stream);
    let server_io = Compat::new(
        TcpStream::connect(server_addr)
            .await
            .with_context(|| format!("failed to connect to {server_addr}"))?,
    );

    let (mut verifier_io, output) = prover
        .prove(verifier_io, server_io)
        .await
        .context("TLSNotary prover failed")?;

    info!(
        request_len = output.sent.len(),
        response_len = output.received.len(),
        "Prover finished MPC-TLS"
    );

    let verification = VerificationOutcome::read_from(&mut verifier_io)
        .await
        .context("failed to read verification outcome")?;
    verifier_io
        .close()
        .await
        .context("failed to close verifier stream")?;

    Ok(NotarizedFlow {
        verification,
        commitment_count: output.transcript_commitments.len(),
        transcript_commitments: output.transcript_commitments,
        transcript_secrets: output.transcript_secrets,
        received_transcript: output.received,
    })
}

pub async fn fetch_server_config(config: &DemoConnectionConfig) -> Result<ServerConfigResponse> {
    send_json_request::<(), ServerConfigResponse>(config, Method::GET, "/api/config", None).await
}

pub async fn create_transfer(
    config: &DemoConnectionConfig,
    request: &TransferRequest,
) -> Result<TransferResponse> {
    send_json_request(config, Method::POST, "/api/transfers", Some(request)).await
}

fn create_tlsn_request(tx_id: u64) -> Result<Request<Empty<Bytes>>> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("/api/attestations/{tx_id}"))
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::new())
        .context("failed to build TLSN request")
}

fn create_request_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}

fn create_response_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_fields: vec![
            BodyFieldConfig::Quoted(".toUsername".into()),
            BodyFieldConfig::Unquoted(".eligibleForMint".into()),
        ],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![KeyValueCommitConfig::with_padding(
            ".attestation".into(),
            ATTESTATION_LEN,
        )],
    }
}

fn create_prover_config(
    cert_bytes: Vec<u8>,
    server_name: &str,
) -> Result<(TlsClientConfig, TlsCommitConfig), ProverError> {
    let dns = server_name
        .to_string()
        .try_into()
        .map_err(|error| ProverError::InvalidInput {
            context: "DNS server name",
            details: format!("'{server_name}': {error}"),
        })?;
    let tls_client_config = TlsClientConfig::builder()
        .server_name(TlsnServerName::Dns(dns))
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()?;

    let tls_commit_config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .build()?;

    Ok((tls_client_config, tls_commit_config))
}

async fn send_json_request<TRequest, TResponse>(
    config: &DemoConnectionConfig,
    method: Method,
    path: &str,
    payload: Option<&TRequest>,
) -> Result<TResponse>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let body_bytes = match payload {
        Some(payload) => serde_json::to_vec(payload).context("failed to encode request body")?,
        None => Vec::new(),
    };

    let client_config = load_test_client_tls_config(&config.server_cert_path)
        .context("failed to load TLS client configuration")?;
    let stream = TcpStream::connect(config.server_addr)
        .await
        .with_context(|| format!("failed to connect to {}", config.server_addr))?;
    let server_name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
        .with_context(|| format!("invalid server name '{}'", config.server_name))?;
    let tls_stream = TlsConnector::from(Arc::clone(&client_config))
        .connect(server_name, stream)
        .await
        .context("failed to establish TLS connection to demo server")?;
    let stream = TokioIo::new(tls_stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(stream)
        .await
        .context("failed to create HTTP/1 client")?;

    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(body_bytes)))
        .context("failed to build HTTP request")?;

    let request_task = async move {
        let response = sender
            .send_request(request)
            .await
            .context("failed to send HTTPS request")?;
        let status = response.status();
        let response_body = response
            .into_body()
            .collect()
            .await
            .context("failed to collect HTTPS response body")?
            .to_bytes();
        ensure!(
            status.is_success(),
            "server returned {}: {}",
            status,
            String::from_utf8_lossy(&response_body)
        );
        serde_json::from_slice::<TResponse>(&response_body)
            .context("failed to decode HTTPS response body")
    };

    let (connection_result, response_result) = futures::join!(connection, request_task);
    connection_result.context("HTTP client connection failed")?;
    response_result
}
