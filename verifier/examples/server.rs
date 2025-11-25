use std::collections::HashMap;

use server::{app::get_app, handle_connection};

fn main() {
    shared::init_test_logging();

    smol::block_on(async {
        use std::path::Path;

        use smol::net::TcpListener;

        let cert_path = Path::new("test_cert.pem");
        let key_path = Path::new("test_key.pem");

        let test_tls_config = shared::get_or_create_test_tls_config(cert_path, key_path).unwrap();
        let app = get_app(create_test_balances());

        let listener = TcpListener::bind("127.0.0.1:8443")
            .await
            .expect("Failed to bind to port 8443");

        tracing::info!("TLS server listening on 127.0.0.1:8443");
        tracing::info!("Waiting for prover connection...");

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    tracing::info!("Accepted connection from {}", addr);
                    let app = app.clone();
                    let server_config = test_tls_config.server_config.clone();

                    smol::spawn(async move {
                        if let Err(e) = handle_connection(app, server_config, stream).await {
                            tracing::error!("Connection error: {}", e);
                        } else {
                            tracing::info!("Connection handled successfully");
                        }
                    })
                    .detach();
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    });
}

pub fn create_test_balances() -> HashMap<String, u64> {
    let mut balances = HashMap::new();
    balances.insert("alice".to_string(), 100);
    balances
}
