mod error;
mod handler;
mod protocol;

use quinn::Endpoint;
use tracing::{error, info};

pub use error::ProtocolError;
pub use protocol::VerificationOutcome;

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

pub async fn serve(endpoint: Endpoint) {
    info!("Verifier service ready, waiting for QUIC connections");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = self::handler::handle(incoming).await {
                error!(error = %error, "Connection task failed");
            }
        });
    }
}
