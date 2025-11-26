use std::{collections::HashMap, sync::Arc};

use axum::{
    Router,
    routing::{get, post},
};
use chrono::Duration;
use quinn::Endpoint;
use serde::{Deserialize, Serialize};
use smol::lock::{Mutex, Semaphore};
use tlsnotary::TranscriptCommitment;

use crate::{handler::handle, notarization::notarize, session::initialize, verification::verify};

pub mod errors;
pub mod handler;
pub mod notarization;
pub mod session;
pub mod stream;
pub mod verification;

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;
pub const MAX_CONCURRENT_NOTARIZATION_SESSIONS: usize = 1 << 4;

#[derive(Clone)]
pub struct NotaryGlobals {
    pub notarization_config: NotarizationConfig,
    pub store: Arc<Mutex<HashMap<String, SessionPhase>>>,
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
    pub max_sent_data: usize,
    pub max_recv_data: usize,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotarizationResult {
    pub server_name: String,
    pub request: String,
    pub response: String,
    pub response_bytes: Vec<u8>,
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionPhase {
    Notarization,
    Verification(NotarizationResult),
}

pub async fn serve(endpoint: Endpoint) {
    let state = NotaryGlobals::default();

    let router: Router = Router::new()
        .route("/session", post(initialize))
        .route("/notarize", get(notarize))
        .route("/verify", post(verify))
        .with_state(state);

    while let Some(incoming) = endpoint.accept().await {
        smol::spawn(handle(incoming, router.clone())).detach();
    }
}
