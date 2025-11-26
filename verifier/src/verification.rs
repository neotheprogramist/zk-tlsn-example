use std::str::FromStr;

use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use zktlsn::{Proof, bind_commitments_to_keys, verify_proof};

use crate::{NotaryGlobals, SessionPhase, errors::VerificationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRequest {
    /// Session ID from the notarization phase
    pub session_id: String,
    /// The ZK proof to verify
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResponse {
    /// Whether verification succeeded
    pub success: bool,
    /// The server name that was verified
    pub server_name: String,
    /// Fields that were verified with ZK proofs
    pub verified_fields: Vec<String>,
    /// Optional message with additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub async fn verify(
    State(notary_globals): State<NotaryGlobals>,
    Json(request): Json<VerificationRequest>,
) -> impl IntoResponse {
    tracing::info!(session_id = %request.session_id, "Starting ZK proof verification");

    // Get session and validate phase
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

    // Parse the response to get structured access to body fields
    let parsed_response = match parser::redacted::Response::from_str(&notarization_result.response)
    {
        Ok(parsed) => parsed,
        Err(e) => {
            tracing::error!("Failed to parse response: {:?}", e);
            return VerificationError::ResponseParseError(format!("{:?}", e)).into_response();
        }
    };

    // Bind commitments to keys in the parsed response
    let bindings = match bind_commitments_to_keys(
        &parsed_response,
        &notarization_result.transcript_commitments,
    ) {
        Ok(bindings) => bindings,
        Err(e) => {
            tracing::error!("Failed to bind commitments: {:?}", e);
            return VerificationError::CommitmentBindingFailed(e.to_string()).into_response();
        }
    };

    if bindings.is_empty() {
        return VerificationError::NoCommitmentsFound.into_response();
    }

    let verified_fields: Vec<String> = bindings.keys().cloned().collect();
    tracing::info!(
        session_id = %request.session_id,
        fields = ?verified_fields,
        "Found {} commitment bindings",
        bindings.len()
    );

    // Verify the ZK proof
    tracing::info!(
        session_id = %request.session_id,
        proof_len = request.proof.proof.len(),
        vk_len = request.proof.verification_key.len(),
        "Verifying ZK proof"
    );

    if let Err(e) = verify_proof(&request.proof) {
        tracing::error!(
            session_id = %request.session_id,
            "ZK proof verification failed: {:?}",
            e
        );
        return VerificationError::ProofVerificationFailed(e.to_string()).into_response();
    }

    tracing::info!(
        session_id = %request.session_id,
        server_name = %notarization_result.server_name,
        "ZK proof verification successful"
    );

    let response = VerificationResponse {
        success: true,
        server_name: notarization_result.server_name,
        verified_fields,
        message: Some("ZK proof verified successfully".to_string()),
    };

    (StatusCode::OK, Json(response)).into_response()
}
