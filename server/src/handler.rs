use std::sync::Arc;

use async_compat::Compat;
use axum::Router;
use futures::io::{AsyncRead, AsyncWrite};
use futures_rustls::TlsAcceptor;
use hyper::{Request, body::Incoming};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tower::Service;

use crate::executor::SmolExecutor;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error(transparent)]
    TlsHandshake(#[from] std::io::Error),

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
    tracing::info!(
        component = "server",
        phase = "tls_handshake",
        status = "started"
    );
    let tls_acceptor = TlsAcceptor::from(server_config);
    let stream = tls_acceptor.accept(cnx).await?;
    tracing::info!(
        component = "server",
        phase = "tls_handshake",
        status = "completed"
    );

    let stream = TokioIo::new(Compat::new(stream));

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    tracing::info!(
        component = "server",
        phase = "serve_connection",
        status = "started"
    );
    hyper_util::server::conn::auto::Builder::new(SmolExecutor::default())
        .serve_connection_with_upgrades(stream, hyper_service)
        .await
        .unwrap();
    tracing::info!(
        component = "server",
        phase = "serve_connection",
        status = "completed"
    );

    Ok(())
}
