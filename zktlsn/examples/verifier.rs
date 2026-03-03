use std::{net::SocketAddr, path::Path};

use quinn::Endpoint;
use shared::{TestQuicConfig, get_or_create_test_quic_config, init_logging};
use tracing::error;
use verifier::serve;

type ExampleResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    init_logging("info");

    smol::block_on(async {
        if let Err(err) = run().await {
            error!(error = %err, "Verifier example failed");
            std::process::exit(1);
        }
    });
}

async fn run() -> ExampleResult<()> {
    let TestQuicConfig { server_config, .. } =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await?;
    let addr: SocketAddr = "[::1]:5000".parse()?;

    let endpoint = Endpoint::server(server_config, addr)?;
    tracing::info!("Reliable streams server listening on {}", addr);
    serve(endpoint).await;
    Ok(())
}
