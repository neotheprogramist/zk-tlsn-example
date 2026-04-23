use std::time::Duration;

use thiserror::Error;
use tokio::io::join;
use tracing::{error, info, warn};

use super::protocol::run_notarize_stream;

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to accept connection: {0}")]
    Accept(#[from] quinn::ConnectionError),
}

pub async fn handle(incoming: quinn::Incoming) -> Result<(), HandlerError> {
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
