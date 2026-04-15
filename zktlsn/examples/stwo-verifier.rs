use std::{net::SocketAddr, path::Path, time::Duration};

use quinn::Endpoint;
use shared::{TestQuicConfig, get_or_create_test_quic_config, init_logging};
use tokio::io::join;
use tracing::{error, info, warn};
use verifier::protocol::run_notarize_only_stream;

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

type ExampleResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    init_logging("info");

    smol::block_on(async {
        if let Err(err) = run().await {
            error!(error = %err, "Stwo verifier failed");
            std::process::exit(1);
        }
    });
}

async fn run() -> ExampleResult<()> {
    let TestQuicConfig { server_config, .. } =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await?;
    let addr: SocketAddr = "[::1]:5001".parse()?;
    let endpoint = Endpoint::server(server_config, addr)?;
    info!("Stwo verifier listening on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
        smol::spawn(async move {
            let connection = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to accept QUIC connection");
                    return;
                }
            };
            let remote_addr = connection.remote_address();
            info!(%remote_addr, "Accepted QUIC connection");

            loop {
                let (send, recv) = match connection.accept_bi().await {
                    Ok(s) => s,
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
                    Err(e) => {
                        error!(error = %e, "Stream error");
                        break;
                    }
                };
                let stream_id = send.id();
                smol::spawn(async move {
                    info!(%stream_id, "Starting notarization on stream");
                    let pipeline = run_notarize_only_stream(join(recv, send));
                    match smol::future::or(pipeline, async {
                        smol::Timer::after(SESSION_TIMEOUT).await;
                        Err(verifier::ProtocolError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "notarization session timed out",
                        )))
                    })
                    .await
                    {
                        Ok(()) => info!(%stream_id, "Notarization complete"),
                        Err(e) if e.to_string().contains("timed out") => {
                            warn!(%stream_id, "Session timed out");
                        }
                        Err(e) => error!(%stream_id, error = %e, "Notarization failed"),
                    }
                })
                .detach();
            }

            info!(%remote_addr, "Connection closed");
        })
        .detach();
    }

    Ok(())
}
