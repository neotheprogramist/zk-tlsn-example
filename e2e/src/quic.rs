use std::net::SocketAddr;

use anyhow::{Context, Result};
use async_compat::Compat;
use futures::{AsyncRead, AsyncWrite};
use quinn::Endpoint;
use tokio::io::join;

pub async fn connect_verifier(
    addr: SocketAddr,
    client_config: quinn::ClientConfig,
) -> Result<impl AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    let mut endpoint = Endpoint::client("[::]:0".parse().context("invalid client bind address")?)
        .context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;

    Ok(Compat::new(join(recv, send)))
}

pub async fn accept_prover(
    listen_addr: SocketAddr,
    server_config: quinn::ServerConfig,
) -> Result<impl AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    let endpoint = Endpoint::server(server_config, listen_addr)
        .with_context(|| format!("failed to bind QUIC server on {listen_addr}"))?;

    let incoming = endpoint
        .accept()
        .await
        .context("QUIC endpoint closed before any connection arrived")?;
    let connection = incoming.await.context("failed to accept QUIC connection")?;
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("failed to accept QUIC bidirectional stream")?;

    Ok(Compat::new(join(recv, send)))
}
