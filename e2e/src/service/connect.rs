use std::net::SocketAddr;
use std::sync::Arc;

use salvo::Error as SalvoError;
use salvo::handler;
use salvo::http::StatusError;
use salvo::prelude::{Depot, Request, Response, Writer};
use salvo::{async_trait, proto};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::verifier::ProtocolError;
use crate::verifier::protocol::run_notarize_stream;

const MAX_PREAMBLE_BYTES: usize = 256;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub allowed_target: SocketAddr,
    pub allowed_host: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("webtransport failed: {0}")]
    WebTransport(#[from] SalvoError),
    #[error("webtransport accept_bi failed: {0}")]
    AcceptBi(#[from] salvo_http3::error::StreamError),
    #[error("connect state missing from depot")]
    StateMissing,
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error(transparent)]
    Preamble(#[from] PreambleError),
    #[error("proxy target `{actual}` is not permitted (expected `{expected}`)")]
    TargetNotAllowed { actual: String, expected: String },
    #[error("failed to open tcp connection: {0}")]
    TcpConnect(#[source] std::io::Error),
    #[error(transparent)]
    Forward(#[from] ForwardError),
    #[error(transparent)]
    Verifier(#[from] ProtocolError),
}

#[derive(Debug, thiserror::Error)]
pub enum PreambleError {
    #[error("preamble missing newline within {0} bytes")]
    TooLong(usize),
    #[error("preamble `{0}` is not a recognised role (expected `VERIFY` or `CONNECT host:port`)")]
    UnknownRole(String),
    #[error("preamble target `{0}` is not host:port")]
    InvalidTarget(String),
    #[error("preamble port `{0}` is not a number")]
    InvalidPort(String),
    #[error(transparent)]
    Read(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("wt\u{2192}tcp forward failed: {0}")]
pub struct ForwardError(#[from] pub std::io::Error);

#[derive(Debug, PartialEq, Eq)]
enum Role {
    Verify,
    Connect { host: String, port: u16 },
}

async fn read_role_preamble<R>(mut recv: R) -> Result<(Role, Vec<u8>), PreambleError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::<u8>::with_capacity(MAX_PREAMBLE_BYTES);
    let mut tmp = [0u8; MAX_PREAMBLE_BYTES];
    loop {
        if buf.len() >= MAX_PREAMBLE_BYTES {
            return Err(PreambleError::TooLong(MAX_PREAMBLE_BYTES));
        }
        let read = recv.read(&mut tmp[..]).await?;
        if read == 0 {
            return Err(PreambleError::TooLong(MAX_PREAMBLE_BYTES));
        }
        buf.extend_from_slice(&tmp[..read]);
        if let Some(idx) = buf.iter().position(|&b| b == b'\n') {
            let line = std::str::from_utf8(&buf[..idx])
                .map_err(|_| PreambleError::UnknownRole(String::new()))?;
            let role = parse_role(line)?;
            let leftover = buf.split_off(idx + 1);
            return Ok((role, leftover));
        }
    }
}

fn parse_role(line: &str) -> Result<Role, PreambleError> {
    if line == "VERIFY" {
        return Ok(Role::Verify);
    }
    if let Some(rest) = line.strip_prefix("CONNECT ") {
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| PreambleError::InvalidTarget(rest.to_string()))?;
        let port: u16 = port
            .parse()
            .map_err(|_| PreambleError::InvalidPort(port.to_string()))?;
        return Ok(Role::Connect {
            host: host.to_string(),
            port,
        });
    }
    Err(PreambleError::UnknownRole(line.to_string()))
}

#[cfg(test)]
mod preamble_tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    async fn parse(bytes: &[u8]) -> Result<(Role, Vec<u8>), PreambleError> {
        let (mut writer, reader) = duplex(1024);
        writer.write_all(bytes).await.unwrap();
        drop(writer);
        read_role_preamble(reader).await
    }

    #[tokio::test]
    async fn recognises_verify_role() {
        let (role, leftover) = parse(b"VERIFY\n").await.unwrap();
        assert_eq!(role, Role::Verify);
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn recognises_verify_with_leftover() {
        let (role, leftover) = parse(b"VERIFY\n\x01\x02\x03").await.unwrap();
        assert_eq!(role, Role::Verify);
        assert_eq!(leftover, b"\x01\x02\x03");
    }

    #[tokio::test]
    async fn recognises_connect_role() {
        let (role, leftover) = parse(b"CONNECT 127.0.0.1:8443\n").await.unwrap();
        assert_eq!(
            role,
            Role::Connect {
                host: "127.0.0.1".into(),
                port: 8443,
            }
        );
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn connect_preserves_leftover() {
        let (role, leftover) = parse(b"CONNECT example.com:80\nGET /").await.unwrap();
        assert_eq!(
            role,
            Role::Connect {
                host: "example.com".into(),
                port: 80,
            }
        );
        assert_eq!(leftover, b"GET /");
    }

    #[tokio::test]
    async fn rejects_unknown_role() {
        let err = parse(b"HELLO\n").await.unwrap_err();
        assert!(matches!(err, PreambleError::UnknownRole(_)));
    }

    #[tokio::test]
    async fn rejects_connect_without_port() {
        let err = parse(b"CONNECT example.com\n").await.unwrap_err();
        assert!(matches!(err, PreambleError::InvalidTarget(_)));
    }

    #[tokio::test]
    async fn rejects_connect_with_nonnumeric_port() {
        let err = parse(b"CONNECT example.com:http\n").await.unwrap_err();
        assert!(matches!(err, PreambleError::InvalidPort(_)));
    }

    #[tokio::test]
    async fn rejects_oversized_preamble() {
        let mut giant = b"CONNECT ".to_vec();
        giant.extend(std::iter::repeat_n(b'a', MAX_PREAMBLE_BYTES));
        giant.push(b'\n');
        let err = parse(&giant).await.unwrap_err();
        assert!(matches!(err, PreambleError::TooLong(_)));
    }

    #[tokio::test]
    async fn rejects_missing_newline() {
        let err = parse(b"VERIFY").await.unwrap_err();
        assert!(matches!(err, PreambleError::TooLong(_)));
    }
}

#[async_trait]
impl Writer for ConnectError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        tracing::warn!(error = %self, "connect handshake failed");
        let status = match &self {
            Self::StateMissing => StatusError::internal_server_error(),
            _ => StatusError::bad_gateway(),
        };
        res.render(status);
    }
}

#[handler]
pub async fn handle(req: &mut Request, depot: &mut Depot) -> Result<(), ConnectError> {
    let proxy_config = depot
        .obtain::<Arc<ProxyConfig>>()
        .map_err(|_| ConnectError::StateMissing)?
        .clone();

    let session = req.web_transport_mut().await?;
    tracing::debug!("connect: session handshake ready");

    loop {
        let Some(accepted) = session.accept_bi().await? else {
            tracing::debug!("connect: session closed");
            return Ok(());
        };
        let proto::webtransport::server::AcceptedBi::BidiStream(_, stream) = accepted else {
            tracing::warn!("connect: expected bidirectional stream, dropping");
            continue;
        };

        let proxy_config = Arc::clone(&proxy_config);
        tokio::spawn(async move {
            let (wt_send, wt_recv) = proto::quic::BidiStream::split(stream);
            if let Err(err) = dispatch_stream(wt_recv, wt_send, &proxy_config).await {
                tracing::warn!(%err, "connect: stream failed");
            }
        });
    }
}

async fn dispatch_stream<R, W>(
    mut wt_recv: R,
    wt_send: W,
    proxy_config: &ProxyConfig,
) -> Result<(), StreamError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (role, leftover) = read_role_preamble(&mut wt_recv).await?;
    match role {
        Role::Verify => {
            if !leftover.is_empty() {
                tracing::warn!(
                    leftover_bytes = leftover.len(),
                    "VERIFY stream had bytes before TLSN session; proceeding"
                );
            }
            let joined = tokio::io::join(ChainedRead::new(leftover, wt_recv), wt_send);
            run_notarize_stream(joined).await?;
            Ok(())
        }
        Role::Connect { host, port } => {
            proxy_connect(wt_recv, wt_send, proxy_config, host, port, leftover).await
        }
    }
}

async fn proxy_connect<R, W>(
    mut wt_recv: R,
    wt_send: W,
    proxy_config: &ProxyConfig,
    host: String,
    port: u16,
    leftover: Vec<u8>,
) -> Result<(), StreamError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if host != proxy_config.allowed_host || port != proxy_config.allowed_target.port() {
        return Err(StreamError::TargetNotAllowed {
            actual: format!("{host}:{port}"),
            expected: format!(
                "{}:{}",
                proxy_config.allowed_host,
                proxy_config.allowed_target.port()
            ),
        });
    }

    let mut tcp = tokio::net::TcpStream::connect(proxy_config.allowed_target)
        .await
        .map_err(StreamError::TcpConnect)?;
    tracing::debug!(target = %proxy_config.allowed_target, "connect(proxy): tcp connected");

    let (tcp_read, mut tcp_write) = tcp.split();

    if !leftover.is_empty() {
        tcp_write
            .write_all(&leftover)
            .await
            .map_err(|e| StreamError::Forward(ForwardError(e)))?;
    }

    let (wt_to_tcp, tcp_to_wt) = tokio::join!(
        forward_wt_to_tcp(&mut wt_recv, tcp_write),
        forward_tcp_to_wt(tcp_read, wt_send),
    );
    wt_to_tcp.map_err(|e| StreamError::Forward(ForwardError(e)))?;
    tcp_to_wt.map_err(|e| StreamError::Forward(ForwardError(e)))?;
    Ok(())
}

// WT→TCP: on EOF, flush TCP and keep the write half open. The demo ledger may
// still be writing its response; closing would half-close too early.
async fn forward_wt_to_tcp<R, W>(mut src: R, mut dst: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let read = src.read(&mut buf).await?;
        if read == 0 {
            dst.flush().await.ok();
            return Ok(());
        }
        dst.write_all(&buf[..read]).await?;
    }
}

// TCP→WT: on EOF, shut down the WT write half so the browser prover sees a
// clean end-of-response instead of hanging on a read.
async fn forward_tcp_to_wt<R, W>(mut src: R, mut dst: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let read = src.read(&mut buf).await?;
        if read == 0 {
            dst.shutdown().await.ok();
            return Ok(());
        }
        dst.write_all(&buf[..read]).await?;
    }
}

// Glues the preamble leftover bytes back onto the front of the reader so the
// verifier pipeline sees the full stream tail starting at byte 0 post-preamble.
pub(crate) struct ChainedRead<R> {
    buf: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> ChainedRead<R> {
    fn new(buf: Vec<u8>, inner: R) -> Self {
        Self { buf, pos: 0, inner }
    }
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for ChainedRead<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            let remaining = &this.buf[this.pos..];
            let n = remaining.len().min(out.remaining());
            out.put_slice(&remaining[..n]);
            this.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, out)
    }
}
