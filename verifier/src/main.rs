use std::{net::SocketAddr, path::Path};

use quinn::Endpoint;
use shared::{get_or_create_test_quic_config, init_logging};
use tracing::error;

fn main() {
    init_logging("info");

    smol::block_on(async {
        if let Err(err) = run().await {
            error!(error = %err, "Verifier server failed");
            std::process::exit(1);
        }
    });
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let test_quic_config =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await?;
    let addr: SocketAddr = "[::1]:5000".parse()?;

    let endpoint = Endpoint::server(test_quic_config.server_config, addr)?;
    tracing::info!(%addr, "Verifier QUIC server listening");

    verifier::serve(endpoint).await;
    Ok(())
}
