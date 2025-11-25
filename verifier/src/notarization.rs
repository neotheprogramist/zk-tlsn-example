use axum::{extract::State, response::IntoResponse};

use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};

use crate::{NotaryGlobals, stream::StreamUpgrade};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequest {
    pub session_id: String,
}

pub async fn notarize(
    stream_upgrade: StreamUpgrade,
    State(notary_globals): State<NotaryGlobals>,
) -> impl IntoResponse {
    let upgraded = TokioIo::new(stream_upgrade.upgraded);
}
