use std::{collections::HashMap, sync::Arc};

use axum::{
    Router,
    routing::{get, post},
};
use chrono::Duration;
use quinn::Endpoint;
use serde::{Deserialize, Serialize};
use smol::lock::{Mutex, Semaphore};

use crate::{handler::handle, notarization::notarize, session::initialize, verification::verify};

pub mod errors;
pub mod handler;
pub mod notarization;
pub mod session;
pub mod stream;
pub mod verification;

/// Maximum sent data size for tests (4 KB)
pub const MAX_SENT_DATA: usize = 1 << 12;
/// Maximum received data size for tests (16 KB)
pub const MAX_RECV_DATA: usize = 1 << 14;
/// Maximum concurrent notarization session (16)
pub const MAX_CONCURRENT_NOTARIZATION_SESSIONS: usize = 1 << 4;

/// Global data that needs to be shared with the axum handlers
#[derive(Clone)]
pub struct NotaryGlobals {
    pub notarization_config: NotarizationConfig,
    /// A temporary storage to store session_id
    pub store: Arc<Mutex<HashMap<String, SessionPhase>>>,
    /// A semaphore to acquire a permit for notarization
    pub semaphore: Arc<Semaphore>,
}
impl Default for NotaryGlobals {
    fn default() -> Self {
        Self {
            notarization_config: Default::default(),
            store: Default::default(),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_NOTARIZATION_SESSIONS)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotarizationConfig {
    /// Global limit for maximum number of bytes that can be sent
    pub max_sent_data: usize,
    /// Global limit for maximum number of bytes that can be received
    pub max_recv_data: usize,
    /// Number of seconds before notarization timeouts to prevent unreleased
    /// memory
    pub timeout: Duration,
}
impl Default for NotarizationConfig {
    fn default() -> Self {
        Self {
            max_sent_data: MAX_SENT_DATA,
            max_recv_data: MAX_RECV_DATA,
            timeout: Duration::seconds(120),
        }
    }
}

/// Data stored after notarization completes, containing the verified transcript
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotarizationResult {
    /// The server name that was connected to
    pub server_name: String,
    /// The HTTP request data (sent by prover)
    pub request: String,
    /// The HTTP response data (received by prover)
    pub response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionPhase {
    Notarization,
    Verification(NotarizationResult),
}

pub async fn serve(endpoint: Endpoint) {
    let state = NotaryGlobals::default();

    let router: Router = Router::new()
        .route("/session", post(initialize))
        .route("/notarize", get(notarize))
        .route("/verify", get(verify))
        .with_state(state);

    while let Some(incoming) = endpoint.accept().await {
        smol::spawn(handle(incoming, router.clone())).detach();
    }
}
