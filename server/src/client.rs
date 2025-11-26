use std::{
    error::Error,
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

type CapturedBytes = Arc<Mutex<Vec<u8>>>;

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
    #[error(transparent)]
    InvalidServerName(#[from] rustls::pki_types::InvalidDnsNameError),

    #[error(transparent)]
    TlsConnection(#[from] std::io::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),
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
    let server_name = ServerName::try_from("localhost")?;
    let tls_connector = TlsConnector::from(client_config);
    let stream = tls_connector.connect(server_name, cnx).await?;

    let (capturing_stream, captured_read_bytes, captured_write_bytes) =
        CapturingStream::new(stream);
    let stream = TokioIo::new(Compat::new(capturing_stream));

    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;

    let request_task = async move {
        let req = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .header("Connection", "close")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::new()))
            .expect("valid request");

        let res = sender.send_request(req).await?;
        let status = res.status();
        let body = res.into_body().collect().await?.to_bytes().to_vec();

        Ok::<_, ClientError>((status, body))
    };

    let (conn_result, response) = futures::join!(conn, request_task);
    response?;

    let raw_request = captured_write_bytes.lock().unwrap().clone();
    let raw_response = captured_read_bytes.lock().unwrap().clone();

    // BrokenPipe is expected when server closes connection first
    if let Err(e) = conn_result {
        if let Some(io_err) = e.source().and_then(|s| s.downcast_ref::<std::io::Error>())
            && io_err.kind() == std::io::ErrorKind::BrokenPipe
        {
            return Ok(CapturedTraffic {
                raw_request,
                raw_response,
            });
        }
        return Err(ClientError::Hyper(e));
    }

    Ok(CapturedTraffic {
        raw_request,
        raw_response,
    })
}
