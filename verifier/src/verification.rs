use axum::{extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::NotaryGlobals;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRequest {
    pub session_id: String,
}

pub async fn verify(State(notary_globals): State<NotaryGlobals>) -> impl IntoResponse {}
