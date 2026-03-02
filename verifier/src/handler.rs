use thiserror::Error;
use tokio::io::join;
use tracing::{error, info};

use crate::protocol::run_notarize_and_verify_stream;

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
        smol::spawn(async move {
            info!(%stream_id, "Starting notarize+verify pipeline on stream");
            if let Err(error) = run_notarize_and_verify_stream(stream).await {
                error!(%stream_id, error = %error, "Pipeline failed");
            } else {
                info!(%stream_id, "Pipeline completed");
            }
        })
        .detach();
    }

    info!(%remote_addr, "Connection closed");
    Ok(())
}
