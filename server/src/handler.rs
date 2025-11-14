use std::sync::Arc;

use async_compat::Compat;
use axum::Router;
use futures::io::{AsyncRead, AsyncWrite};
use futures_rustls::TlsAcceptor;
use hyper::{Request, body::Incoming};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tower::Service;
use tracing::info;

use crate::executor::SmolExecutor;

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
    // futures-rustls accepts futures::io traits directly (which smol uses)
    let stream = tls_acceptor
        .accept(cnx)
        .await
        .map_err(ConnectionError::TlsHandshake)?;

    // Wrap the futures-io TLS stream with Compat to convert to tokio traits,
    // then wrap with TokioIo to convert to hyper's Read/Write traits
    let stream = TokioIo::new(Compat::new(stream));

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    hyper_util::server::conn::auto::Builder::new(SmolExecutor::new())
        .serve_connection_with_upgrades(stream, hyper_service)
        .await
        .map_err(ConnectionError::ServeConnection)?;

    info!("Connection handled successfully");
    Ok(())
}
