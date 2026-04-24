pub mod app;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use salvo::{Service, conn::SocketAddr as SalvoSocketAddr, http::uri::Scheme};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::{
    server::app::{AppConfig, InitialUser, get_app},
    tls::get_or_create_test_tls_config,
};

pub struct DemoServerConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Error)]
enum ConnectionError {
    #[error(transparent)]
    TlsHandshake(#[from] std::io::Error),

    #[error(transparent)]
    ServeConnection(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub async fn serve(cfg: DemoServerConfig) -> Result<()> {
    let tls = get_or_create_test_tls_config(&cfg.cert_path, &cfg.key_path)
        .context("failed to load or create TLS server configuration")?;
    let server_config = tls.server_config;
    let router = get_app(demo_app_config()).context("failed to build server app")?;
    let service = Arc::new(Service::new(router));
    let listener = TcpListener::bind(cfg.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen_addr))?;

    tracing::info!(listen_addr = %cfg.listen_addr, "TLS demo server listening");

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("failed to accept connection")?;
        let service = Arc::clone(&service);
        let server_config = server_config.clone();

        tracing::info!(%addr, "Accepted connection");
        tokio::spawn(async move {
            if let Err(error) = handle_connection(service, server_config, stream).await {
                tracing::error!(error = %error, "Connection error");
            }
        });
    }
}

async fn handle_connection(
    service: Arc<Service>,
    server_config: Arc<rustls::ServerConfig>,
    cnx: TcpStream,
) -> Result<(), ConnectionError> {
    let stream = TlsAcceptor::from(server_config).accept(cnx).await?;
    let hyper_handler = service.hyper_handler(
        SalvoSocketAddr::Unknown,
        SalvoSocketAddr::Unknown,
        Scheme::HTTPS,
        None,
        None,
    );
    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), hyper_handler)
        .await?;
    Ok(())
}

fn demo_app_config() -> AppConfig {
    AppConfig {
        users: vec![
            InitialUser::new("alice", 100),
            InitialUser::new("bob", 40),
            InitialUser::new("treasury", 0),
        ],
        special_username: String::from("treasury"),
    }
}
