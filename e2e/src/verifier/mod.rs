mod error;
pub mod protocol;

use std::time::Duration;

use quinn::Endpoint;
use thiserror::Error;
use tokio::io::join;
use tracing::{error, info, warn};

pub use error::ProtocolError;
pub use protocol::VerificationOutcome;

use self::protocol::run_notarize_stream;

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
enum HandlerError {
    #[error("failed to accept connection: {0}")]
    Accept(#[from] quinn::ConnectionError),
}

pub async fn serve(endpoint: Endpoint) {
    info!("Verifier service ready, waiting for QUIC connections");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = handle(incoming).await {
                error!(error = %error, "Connection task failed");
            }
        });
    }
}

async fn handle(incoming: quinn::Incoming) -> Result<(), HandlerError> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    info!(%remote_addr, "Accepted QUIC connection");

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(error) => return Err(error.into()),
        };

        let stream_id = send.id();
        let stream = join(recv, send);
        tokio::spawn(async move {
            info!(%stream_id, "Starting notarize pipeline on stream");
            match tokio::time::timeout(SESSION_TIMEOUT, run_notarize_stream(stream)).await {
                Ok(Ok(())) => info!(%stream_id, "Pipeline completed"),
                Ok(Err(error)) => error!(%stream_id, error = %error, "Pipeline failed"),
                Err(_) => warn!(
                    %stream_id,
                    timeout_secs = SESSION_TIMEOUT.as_secs(),
                    "Session timed out"
                ),
            }
        });
    }

    info!(%remote_addr, "Connection closed");
    Ok(())
}
