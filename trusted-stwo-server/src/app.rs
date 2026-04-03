use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use chrono::Utc;

use crate::{
    error::ApiError,
    signing::Signer,
    types::{HealthResponse, PublicKeyResponse, VerifyAndSignRequest, VerifyAndSignResponse},
    verify::verify_raw_stwo_proof,
};

#[derive(Clone)]
pub struct AppState {
    pub signer: Arc<Signer>,
}

pub fn router(signer: Arc<Signer>) -> Router {
    let state = AppState { signer };

    Router::new()
        .route("/health", get(health))
        .route("/public-key", get(public_key))
        .route("/verify-and-sign", post(verify_and_sign))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn public_key(State(state): State<AppState>) -> Json<PublicKeyResponse> {
    Json(PublicKeyResponse {
        signer_public_key_hex: state.signer.public_key_hex(),
        signer_address: state.signer.address_hex(),
    })
}

async fn verify_and_sign(
    State(state): State<AppState>,
    Json(req): Json<VerifyAndSignRequest>,
) -> Result<Json<VerifyAndSignResponse>, ApiError> {
    let verified = verify_raw_stwo_proof(&req)?;

    let msg_hash_vec = hex::decode(&verified.message_hash_hex)
        .map_err(|e| ApiError::Internal(format!("invalid message hash hex: {e}")))?;
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&msg_hash_vec);
    let sig = state
        .signer
        .sign_digest(msg_hash)
        .map_err(ApiError::Internal)?;

    Ok(Json(VerifyAndSignResponse {
        proof_id: req.proof_id,
        verified: true,
        proof_hash_hex: verified.proof_hash_hex,
        claim_hash_hex: verified.claim_hash_hex,
        message_hash_hex: verified.message_hash_hex,
        signature_hex: format!("0x{}", hex::encode(sig.signature_65)),
        signature_r_hex: format!("0x{}", hex::encode(sig.r)),
        signature_s_hex: format!("0x{}", hex::encode(sig.s)),
        signature_v: sig.v,
        signer_address: state.signer.address_hex(),
        signer_public_key_hex: state.signer.public_key_hex(),
        signed_at_unix: Utc::now().timestamp(),
    }))
}
