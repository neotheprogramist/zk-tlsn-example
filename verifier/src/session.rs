use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{NotaryGlobals, SessionPhase};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub max_sent_data: Option<usize>,
    pub max_recv_data: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    pub session_id: String,
}

pub async fn initialize(State(notary_globals): State<NotaryGlobals>) -> impl IntoResponse {
    let session_id = Uuid::new_v4().to_string();
    notary_globals
        .store
        .lock()
        .await
        .insert(session_id.clone(), SessionPhase::Notarization);
    Json(NotarizationSessionResponse { session_id })
}
