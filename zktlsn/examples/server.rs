use std::collections::HashMap;

use server::{app::get_app, handle_connection};
use tracing::error;

type ExampleResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    shared::init_logging("info");

    smol::block_on(async {
        if let Err(err) = run().await {
            error!(error = %err, "TLS server example failed");
            std::process::exit(1);
        }
    });
}

async fn run() -> ExampleResult<()> {
    use std::path::Path;

    use smol::net::TcpListener;

    let cert_path = Path::new("test_cert.pem");
    let key_path = Path::new("test_key.pem");
    let test_tls_config = shared::get_or_create_test_tls_config(cert_path, key_path)?;
    let app = get_app(create_test_balances());
    let listener = TcpListener::bind("localhost:8443").await?;

    tracing::info!("TLS server listening on localhost:8443");
    tracing::info!("Waiting for prover connection...");

    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::info!("Accepted connection from {}", addr);
        let app = app.clone();
        let server_config = test_tls_config.server_config.clone();

        smol::spawn(async move {
            if let Err(error) = handle_connection(app, server_config, stream).await {
                tracing::error!(error = %error, "Connection error");
                return;
            }
            tracing::info!("Connection handled successfully");
        })
        .detach();
    }
}

pub fn create_test_balances() -> HashMap<String, u64> {
    let mut balances = HashMap::new();
    balances.insert("alice".to_string(), 100);
    balances
}
