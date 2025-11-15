use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use async_compat::Compat;
use axum::body::Bytes;
use futures::io::{AsyncRead, AsyncWrite};
use futures_rustls::TlsConnector;
use http_body_util::{BodyExt, Full};
use hyper::Uri;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tracing::info;

type CapturedBytes = Arc<Mutex<Vec<u8>>>;

/// Wrapper that captures all read and write bytes from the underlying stream
struct CapturingStream<S> {
    inner: S,
    captured_read: CapturedBytes,
    captured_write: CapturedBytes,
}

impl<S> CapturingStream<S> {
    fn new(inner: S) -> (Self, CapturedBytes, CapturedBytes) {
        let captured_read = Arc::new(Mutex::new(Vec::new()));
        let captured_write = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inner,
                captured_read: captured_read.clone(),
                captured_write: captured_write.clone(),
            },
            captured_read,
            captured_write,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CapturingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(n)) = result
            && n > 0
            && let Ok(mut captured) = self.captured_read.lock()
        {
            captured.extend_from_slice(&buf[..n]);
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CapturingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(n)) = result
            && n > 0
            && let Ok(mut captured) = self.captured_write.lock()
        {
            captured.extend_from_slice(&buf[..n]);
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

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

pub struct CapturedTraffic {
    pub raw_request: Vec<u8>,
    pub raw_response: Vec<u8>,
}

pub async fn send_request<IO>(
    uri: Uri,
    client_config: Arc<rustls::ClientConfig>,
    cnx: IO,
) -> Result<CapturedTraffic, ClientError>
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

    let (capturing_stream, captured_read_bytes, captured_write_bytes) =
        CapturingStream::new(stream);

    // Convert futures-io to tokio traits, then to hyper's Read/Write
    let stream = TokioIo::new(Compat::new(capturing_stream));

    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream)
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

        Ok::<_, ClientError>((status, body))
    };

    let (conn_result, response) = futures::join!(conn, request_task);
    conn_result.map_err(ClientError::ConnectionTask)?;
    let (status, _body) = response?;

    let raw_request = captured_write_bytes
        .lock()
        .unwrap_or_else(|_| panic!("Failed to lock captured write bytes"))
        .clone();

    let raw_response = captured_read_bytes
        .lock()
        .unwrap_or_else(|_| panic!("Failed to lock captured read bytes"))
        .clone();

    info!("Request sent successfully, status: {}", status);
    Ok(CapturedTraffic {
        raw_request,
        raw_response,
    })
}
