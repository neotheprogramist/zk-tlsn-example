use std::sync::Arc;

use axum::Router;
use hyper::{Request, body::Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::info;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(std::io::Error),

    #[error("Failed to serve connection: {0}")]
    ServeConnection(Box<dyn std::error::Error + Send + Sync>),
}

pub async fn handle_connection<IO>(
    tower_service: Router,
    server_config: Arc<rustls::ServerConfig>,
    cnx: IO,
) -> Result<(), ConnectionError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls_acceptor = TlsAcceptor::from(server_config);
    let stream = tls_acceptor
        .accept(cnx)
        .await
        .map_err(ConnectionError::TlsHandshake)?;

    let stream = TokioIo::new(stream);

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(stream, hyper_service)
        .await
        .map_err(ConnectionError::ServeConnection)?;

    info!("Connection handled successfully");
    Ok(())
}
