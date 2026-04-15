use std::{net::SocketAddr, sync::Arc};

use axum::serve;
use tokio::net::TcpListener;
use trusted_stwo_server::{Signer, router};
use tracing::info;

mod config;
use config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(config.rust_log.clone())
        .init();

    let signer = Arc::new(match config.trusted_server_private_key_hex.as_deref() {
        Some(private_key) => Signer::from_private_key_hex(private_key)?,
        None => Signer::from_env_or_random()?,
    });
    let app = router(signer.clone());

    let addr: SocketAddr = config.trusted_server_addr.parse()?;

    info!(
        address = %addr,
        pubkey = %signer.public_key_hex(),
        "trusted stwo server started"
    );

    let listener = TcpListener::bind(addr).await?;
    serve(listener, app).await?;
    Ok(())
}
