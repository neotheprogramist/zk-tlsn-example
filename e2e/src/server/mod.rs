pub mod app;
pub mod handler;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
pub use handler::{ConnectionError, handle_connection};
use salvo::Service;
use tokio::net::TcpListener;

use crate::{
    server::app::{AppConfig, InitialUser, get_app},
    testing::get_or_create_test_tls_config,
};

pub struct DemoServerConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
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
