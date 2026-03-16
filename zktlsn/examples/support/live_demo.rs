use std::{net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow, ensure};
use async_compat::Compat;
use futures_rustls::TlsConnector;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::{Serialize, de::DeserializeOwned};
use server::app::{ServerConfigResponse, TransferRequest, TransferResponse};
use shared::{TestTlsConfig, get_or_create_test_tls_config};
use smol::net::TcpStream;
use tlsnotary::{
    CertificateDer, MpcTlsConfig, RootCertStore, ServerName as TlsnServerName, TlsClientConfig,
    TlsCommitConfig,
    prover::{KeyValueCommitConfig, RevealConfig},
};

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

#[derive(Debug, Clone)]
pub struct DemoConnectionConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
}

pub fn load_tls_materials() -> Result<TestTlsConfig> {
    get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))
        .context("failed to load TLS test configuration")
}

#[allow(dead_code)]
pub async fn fetch_server_config(config: &DemoConnectionConfig) -> Result<ServerConfigResponse> {
    send_json_request::<(), ServerConfigResponse>(config, Method::GET, "/api/config", None).await
}

pub async fn create_transfer(
    config: &DemoConnectionConfig,
    request: &TransferRequest,
) -> Result<TransferResponse> {
    send_json_request(config, Method::POST, "/api/transfers", Some(request)).await
}

pub fn create_tlsn_request(tx_id: u64) -> Result<Request<Empty<Bytes>>> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("/api/attestations/{tx_id}"))
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::new())
        .map_err(Into::into)
}

pub fn create_request_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}

pub fn create_response_reveal_config() -> RevealConfig {
    use tlsnotary::BodyFieldConfig;

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
            shared::ATTESTATION_LEN,
        )],
    }
}

pub fn create_prover_config(
    cert_bytes: Vec<u8>,
    server_name: &str,
) -> tlsnotary::Result<(TlsClientConfig, TlsCommitConfig)> {
    let tls_client_config = TlsClientConfig::builder()
        .server_name(TlsnServerName::Dns(
            server_name.to_string().try_into().map_err(|error| {
                tlsnotary::Error::InvalidInput(format!(
                    "invalid DNS server name '{server_name}': {error}"
                ))
            })?,
        ))
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
    let body_bytes = payload
        .map(serde_json::to_vec)
        .transpose()
        .context("failed to encode request body")?
        .unwrap_or_default();

    let TestTlsConfig { client_config, .. } = load_tls_materials()?;
    let stream = TcpStream::connect(config.server_addr)
        .await
        .with_context(|| format!("failed to connect to {}", config.server_addr))?;
    let tls_stream = TlsConnector::from(Arc::clone(&client_config))
        .connect(
            rustls::pki_types::ServerName::try_from(config.server_name.clone()).map_err(
                |error| anyhow!("invalid server name '{}': {error}", config.server_name),
            )?,
            stream,
        )
        .await
        .context("failed to establish TLS connection to demo server")?;
    let stream = TokioIo::new(Compat::new(tls_stream));
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
    if let Err(error) = connection_result {
        let broken_pipe = error.to_string().contains("Broken pipe");
        if !broken_pipe {
            return Err(anyhow!(error)).context("HTTP client connection failed");
        }
    }

    response_result
}
