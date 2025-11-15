use std::sync::Arc;

use async_compat::Compat;
use axum::body::Bytes;
use futures::io::{AsyncRead, AsyncWrite};
use futures_rustls::TlsConnector;
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tracing::info;

use crate::executor::SmolExecutor;

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
    pub raw_response: String,
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

    // Wrap the futures-io TLS stream with Compat to convert to tokio traits,
    // then wrap with TokioIo to convert to hyper's Read/Write traits
    let stream = TokioIo::new(Compat::new(stream));

    let (mut sender, conn) = hyper::client::conn::http2::handshake(SmolExecutor::new(), stream)
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
        let headers = res.headers().clone();
        let body = res
            .into_body()
            .collect()
            .await
            .map_err(ClientError::BodyCollection)?
            .to_bytes()
            .to_vec();

        // Build raw HTTP response string in chunked transfer encoding format
        let mut raw_response = format!("HTTP/1.1 {} {}\n", status.as_u16(), status.canonical_reason().unwrap_or(""));

        for (name, value) in headers.iter() {
            raw_response.push_str(&format!("{}: {}\n", name, value.to_str().unwrap_or("")));
        }
        raw_response.push('\n');

        // Add body in chunked format
        if let Ok(body_str) = String::from_utf8(body.clone()) {
            // Write chunk size in hex
            raw_response.push_str(&format!("{:x}\n", body_str.len()));
            // Write chunk data
            raw_response.push_str(&body_str);
            raw_response.push('\n');
            // Write terminating chunk
            raw_response.push_str("0\n");
        }

        Ok::<_, ClientError>(Response { status, body, raw_response })
    };

    let (conn_result, response) = futures::join!(conn, request_task);
    conn_result.map_err(ClientError::ConnectionTask)?;
    let response = response?;

    info!("Request sent successfully, status: {}", response.status);
    Ok(response)
}
