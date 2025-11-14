use std::sync::Arc;

use axum::body::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tracing::info;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Invalid server name: {0}")]
    InvalidServerName(String),

    #[error("TLS connection failed: {0}")]
    TlsConnection(std::io::Error),

    #[error("HTTP/2 handshake failed: {0}")]
    Http2Handshake(hyper::Error),

    #[error("Request failed: {0}")]
    RequestFailed(hyper::Error),

    #[error("Response body collection failed: {0}")]
    BodyCollection(hyper::Error),

    #[error("Connection task failed: {0}")]
    ConnectionTask(#[from] hyper::Error),
}

pub struct Response {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

pub async fn send_request<IO>(
    uri: Uri,
    client_config: Arc<rustls::ClientConfig>,
    cnx: IO,
) -> Result<Response, ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_name = ServerName::try_from("localhost")
        .map_err(|_| ClientError::InvalidServerName("localhost".to_string()))?;

    let tls_connector = TlsConnector::from(client_config);
    let stream = tls_connector
        .connect(server_name, cnx)
        .await
        .map_err(ClientError::TlsConnection)?;

    let stream = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), stream)
        .await
        .map_err(ClientError::Http2Handshake)?;

    let request_task = async move {
        let req = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::new()))
            .expect("valid request");

        let res = sender
            .send_request(req)
            .await
            .map_err(ClientError::RequestFailed)?;

        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .map_err(ClientError::BodyCollection)?
            .to_bytes()
            .to_vec();

        Ok::<_, ClientError>(Response { status, body })
    };

    let (conn_result, response) = tokio::join!(conn, request_task);
    conn_result.map_err(ClientError::ConnectionTask)?;
    let response = response?;

    info!("Request sent successfully, status: {}", response.status);
    Ok(response)
}
