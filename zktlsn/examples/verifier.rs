use std::{net::SocketAddr, path::Path};

use quinn::Endpoint;
use shared::{TestQuicConfig, get_or_create_test_quic_config};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use verifier::serve;

fn main() {
    // Setup Barretenberg SRS (required before proof verification)
    zktlsn::setup_barretenberg_srs().expect("Failed to setup Barretenberg SRS");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
        .with_test_writer()
        .try_init()
        .unwrap();

    smol::block_on(async {
        let TestQuicConfig { server_config, .. } =
            get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await;
        let addr: SocketAddr = "[::1]:5000".parse().unwrap();

        let endpoint = Endpoint::server(server_config, addr).unwrap();
        tracing::info!("Reliable streams server listening on {}", addr);
        serve(endpoint).await;
    });
}
