use std::str::FromStr;

use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use zktlsn::{Proof, bind_commitments_to_keys, verify_proof};

use crate::{NotaryGlobals, SessionPhase, errors::VerificationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRequest {
    pub session_id: String,
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResponse {
    pub success: bool,
    pub server_name: String,
    pub verified_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub async fn verify(
    State(notary_globals): State<NotaryGlobals>,
    Json(request): Json<VerificationRequest>,
) -> impl IntoResponse {
    let notarization_result = {
        let store = notary_globals.store.lock().await;
        match store.get(&request.session_id) {
            Some(SessionPhase::Verification(result)) => result.clone(),
            Some(SessionPhase::Notarization) => {
                return VerificationError::InvalidSessionPhase("Notarization".to_string())
                    .into_response();
            }
            None => {
                return VerificationError::SessionNotFound(request.session_id.clone())
                    .into_response();
            }
        }
    };

    let parsed_response = match parser::redacted::Response::from_str(&notarization_result.response)
    {
        Ok(parsed) => parsed,
        Err(e) => {
            return VerificationError::ResponseParseError(format!("{:?}", e)).into_response();
        }
    };

    let bindings = match bind_commitments_to_keys(
        &parsed_response,
        &notarization_result.transcript_commitments,
    ) {
        Ok(bindings) => bindings,
        Err(e) => {
            return VerificationError::CommitmentBindingFailed(e.to_string()).into_response();
        }
    };

    if bindings.is_empty() {
        return VerificationError::NoCommitmentsFound.into_response();
    }

    let verified_fields: Vec<String> = bindings.keys().cloned().collect();

    if let Err(e) = verify_proof(request.proof) {
        return VerificationError::ProofVerificationFailed(e.to_string()).into_response();
    }

    let response = VerificationResponse {
        success: true,
        server_name: notarization_result.server_name,
        verified_fields,
        message: Some("ZK proof verified successfully".to_string()),
    };

    (StatusCode::OK, Json(response)).into_response()
}
