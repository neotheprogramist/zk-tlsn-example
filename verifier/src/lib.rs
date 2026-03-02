use quinn::Endpoint;
use tracing::{error, info};

use crate::handler::handle;

pub mod errors;
pub mod handler;
pub mod protocol;

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

pub use errors::ProtocolError;
pub use protocol::{ProofMessage, VerificationOutcome};

pub async fn serve(endpoint: Endpoint) {
    info!("Verifier service ready, waiting for QUIC connections");

    while let Some(incoming) = endpoint.accept().await {
        smol::spawn(async move {
            if let Err(error) = handle(incoming).await {
                error!(error = %error, "Connection task failed");
            }
        })
        .detach();
    }
}
