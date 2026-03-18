use std::time::Duration;

use thiserror::Error;
use tokio::io::join;
use tracing::{error, info, warn};

use crate::protocol::run_notarize_and_verify_stream;

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
        smol::spawn(async move {
            info!(%stream_id, "Starting notarize+verify pipeline on stream");
            let pipeline = run_notarize_and_verify_stream(stream);
            match smol::future::or(pipeline, async {
                smol::Timer::after(SESSION_TIMEOUT).await;
                Err(crate::ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "verification session timed out",
                )))
            })
            .await
            {
                Ok(()) => info!(%stream_id, "Pipeline completed"),
                Err(error)
                    if error
                        .to_string()
                        .contains("verification session timed out") =>
                {
                    warn!(%stream_id, timeout_secs = SESSION_TIMEOUT.as_secs(), "Session timed out");
                }
                Err(error) => error!(%stream_id, error = %error, "Pipeline failed"),
            }
        })
        .detach();
    }

    info!(%remote_addr, "Connection closed");
    Ok(())
}
