use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::{Serialize, de::DeserializeOwned};
use tlsnotary::{
    CertificateDer, MpcTlsConfig, RootCertStore, ServerName as TlsnServerName, TlsClientConfig,
    TlsCommitConfig,
    prover::{KeyValueCommitConfig, RevealConfig},
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{
    server::app::{ServerConfigResponse, TransferRequest, TransferResponse},
    testing::load_test_client_tls_config,
    verifier::{MAX_RECV_DATA, MAX_SENT_DATA},
};

#[derive(Debug, Clone)]
pub struct DemoConnectionConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub server_cert_path: PathBuf,
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

pub fn create_tlsn_request(tx_id: u64) -> Result<Request<Empty<Bytes>>> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("/api/attestations/{tx_id}"))
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::new())
        .context("failed to build TLSN request")
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
    let dns = match server_name.to_string().try_into() {
        Ok(dns) => dns,
        Err(error) => {
            return Err(tlsnotary::Error::InvalidInput {
                context: "DNS server name",
                details: format!("'{server_name}': {error}"),
            });
        }
    };
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
