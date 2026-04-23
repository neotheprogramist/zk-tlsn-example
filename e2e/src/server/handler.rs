use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use salvo::{Service, conn::SocketAddr as SalvoSocketAddr, http::uri::Scheme};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tracing::info;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error(transparent)]
    TlsHandshake(#[from] std::io::Error),

    #[error(transparent)]
    ServeConnection(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub async fn handle_connection<IO>(
    service: Arc<Service>,
    server_config: Arc<rustls::ServerConfig>,
    cnx: IO,
) -> Result<(), ConnectionError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("New TLS connection");
    let tls_acceptor = TlsAcceptor::from(server_config);
    let stream = tls_acceptor.accept(cnx).await?;
    let stream = TokioIo::new(stream);

    let hyper_handler = service.hyper_handler(
        SalvoSocketAddr::Unknown,
        SalvoSocketAddr::Unknown,
        Scheme::HTTPS,
        None,
        None,
    );

    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(stream, hyper_handler)
        .await?;

    Ok(())
}
