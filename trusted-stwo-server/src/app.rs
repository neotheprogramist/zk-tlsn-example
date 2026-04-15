use std::{collections::HashMap, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use chrono::Utc;

use crate::{
    error::ApiError,
    signing::Signer,
    types::{
        HealthResponse, PublicKeyResponse, SignTransactionSettlementRequest,
        SignTransactionSettlementResponse, VerifyAndSignRequest, VerifyAndSignResponse,
        VerifyTlsnAndSignSettlementRequest, VerifyTlsnAndSignSettlementResponse,
        VerifyTlsnAndSignTransactionSettlementRequest,
        VerifyTlsnAndSignTransactionSettlementResponse,
    },
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
        .route(
            "/verify-tlsn-and-sign-settlement",
            post(verify_tlsn_and_sign_settlement),
        )
        .route(
            "/verify-tlsn-and-sign-transaction-settlement",
            post(verify_tlsn_and_sign_transaction_settlement),
        )
        .route(
            "/sign-transaction-settlement",
            post(sign_transaction_settlement),
        )
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

    let response = VerifyAndSignResponse {
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
    };

    Ok(Json(response))
}

async fn sign_transaction_settlement(
    State(state): State<AppState>,
    Json(req): Json<SignTransactionSettlementRequest>,
) -> Result<Json<SignTransactionSettlementResponse>, ApiError> {
    let tx_id = decode_hex_32(&req.transaction_id_hex, "transaction_id_hex")?;
    let buyer = decode_hex_20(&req.buyer_address, "buyer_address")?;
    let token = decode_hex_20(&req.token_address, "token_address")?;

    let mut claim_bytes = Vec::with_capacity(24 + 32 * 4 + 20 + 20);
    claim_bytes.extend_from_slice(b"trusted-stwo-claim-v1");
    claim_bytes.extend_from_slice(&tx_id);
    claim_bytes.extend_from_slice(&u256be_from_u64(req.fiat_amount));
    claim_bytes.extend_from_slice(&u256be_from_u64(req.crypto_amount));
    claim_bytes.extend_from_slice(&u256be_from_u64(req.secret_nullifier_hash));
    claim_bytes.extend_from_slice(&buyer);
    claim_bytes.extend_from_slice(&token);
    let claim_hash = keccak256(&claim_bytes);

    let mut message_bytes = Vec::with_capacity(24 + 32);
    message_bytes.extend_from_slice(b"trusted-stwo-message-v1");
    message_bytes.extend_from_slice(&claim_hash);
    let message_hash = keccak256(&message_bytes);

    let sig = state
        .signer
        .sign_digest(message_hash)
        .map_err(ApiError::Internal)?;

    let response = SignTransactionSettlementResponse {
        transaction_id_hex: normalize_hex_prefixed(&req.transaction_id_hex),
        claim_hash_hex: format!("0x{}", hex::encode(claim_hash)),
        message_hash_hex: format!("0x{}", hex::encode(message_hash)),
        signature_hex: format!("0x{}", hex::encode(sig.signature_65)),
        signature_r_hex: format!("0x{}", hex::encode(sig.r)),
        signature_s_hex: format!("0x{}", hex::encode(sig.s)),
        signature_v: sig.v,
        signer_address: state.signer.address_hex(),
        signer_public_key_hex: state.signer.public_key_hex(),
        signed_at_unix: Utc::now().timestamp(),
    };

    Ok(Json(response))
}

async fn verify_tlsn_and_sign_settlement(
    State(state): State<AppState>,
    Json(req): Json<VerifyTlsnAndSignSettlementRequest>,
) -> Result<Json<VerifyTlsnAndSignSettlementResponse>, ApiError> {
    let (_status_line, headers, body) = parse_http_response(&req.transcript_response)?;
    let body_json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| ApiError::InvalidInput(format!("invalid JSON body: {e}")))?;

    let comment_data = body_json
        .get("commentData")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::InvalidInput("missing body field commentData".to_string()))?
        .to_string();
    let rev_tag = body_json
        .get("revTag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::InvalidInput("missing body field revTag".to_string()))?
        .to_string();
    let fiat_amount = body_json
        .get("fiatAmount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ApiError::InvalidInput("missing/invalid body field fiatAmount".to_string()))?;

    let header_sig = headers
        .get("x-revolut-signature")
        .cloned()
        .ok_or_else(|| ApiError::InvalidInput("missing header x-revolut-signature".to_string()))?;
    let expected_sig = sign_transfer_payload(
        &comment_data,
        &rev_tag,
        fiat_amount,
        &std::env::var("MOCK_SIGNATURE_SECRET").unwrap_or_else(|_| "mock-secret".to_string()),
    );
    if !header_sig.trim().eq_ignore_ascii_case(&expected_sig) {
        return Err(ApiError::Verification(
            "mock response signature header mismatch".to_string(),
        ));
    }

    let mut claim_bytes = Vec::new();
    claim_bytes.extend_from_slice(b"trusted-tlsn-settlement-claim-v1");
    claim_bytes.extend_from_slice(&(comment_data.len() as u32).to_be_bytes());
    claim_bytes.extend_from_slice(comment_data.as_bytes());
    claim_bytes.extend_from_slice(&(rev_tag.len() as u32).to_be_bytes());
    claim_bytes.extend_from_slice(rev_tag.as_bytes());
    claim_bytes.extend_from_slice(&u256be_from_u64(fiat_amount));
    let claim_hash = keccak256(&claim_bytes);

    let mut message_bytes = Vec::new();
    message_bytes.extend_from_slice(b"trusted-stwo-message-v1");
    message_bytes.extend_from_slice(&claim_hash);
    let message_hash = keccak256(&message_bytes);

    let sig = state
        .signer
        .sign_digest(message_hash)
        .map_err(ApiError::Internal)?;

    let response = VerifyTlsnAndSignSettlementResponse {
        verified: true,
        comment_data,
        rev_tag,
        fiat_amount,
        claim_hash_hex: format!("0x{}", hex::encode(claim_hash)),
        message_hash_hex: format!("0x{}", hex::encode(message_hash)),
        signature_hex: format!("0x{}", hex::encode(sig.signature_65)),
        signature_r_hex: format!("0x{}", hex::encode(sig.r)),
        signature_s_hex: format!("0x{}", hex::encode(sig.s)),
        signature_v: sig.v,
        signer_address: state.signer.address_hex(),
        signer_public_key_hex: state.signer.public_key_hex(),
        signed_at_unix: Utc::now().timestamp(),
    };

    Ok(Json(response))
}

async fn verify_tlsn_and_sign_transaction_settlement(
    State(state): State<AppState>,
    Json(req): Json<VerifyTlsnAndSignTransactionSettlementRequest>,
) -> Result<Json<VerifyTlsnAndSignTransactionSettlementResponse>, ApiError> {
    let (_status_line, headers, body) = parse_http_response(&req.transcript_response)?;
    let body_json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| ApiError::InvalidInput(format!("invalid JSON body: {e}")))?;

    let comment_data = body_json
        .get("commentData")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::InvalidInput("missing body field commentData".to_string()))?
        .to_string();
    let rev_tag = body_json
        .get("revTag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::InvalidInput("missing body field revTag".to_string()))?
        .to_string();
    let fiat_amount = body_json
        .get("fiatAmount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            ApiError::InvalidInput("missing/invalid body field fiatAmount".to_string())
        })?;

    let header_sig = headers
        .get("x-revolut-signature")
        .cloned()
        .ok_or_else(|| ApiError::InvalidInput("missing header x-revolut-signature".to_string()))?;
    let expected_sig = sign_transfer_payload(
        &comment_data,
        &rev_tag,
        fiat_amount,
        &std::env::var("MOCK_SIGNATURE_SECRET").unwrap_or_else(|_| "mock-secret".to_string()),
    );
    if !header_sig.trim().eq_ignore_ascii_case(&expected_sig) {
        return Err(ApiError::Verification(
            "mock response signature header mismatch".to_string(),
        ));
    }

    let tx_id = decode_hex_32(&req.transaction_id_hex, "transaction_id_hex")?;
    let buyer = decode_hex_20(&req.buyer_address, "buyer_address")?;
    let token = decode_hex_20(&req.token_address, "token_address")?;

    let mut claim_bytes = Vec::with_capacity(21 + 32 + 32 * 4 + 20 + 20);
    claim_bytes.extend_from_slice(b"trusted-stwo-claim-v1");
    claim_bytes.extend_from_slice(&tx_id);
    claim_bytes.extend_from_slice(&u256be_from_u64(fiat_amount));
    claim_bytes.extend_from_slice(&u256be_from_u64(req.crypto_amount));
    claim_bytes.extend_from_slice(&u256be_from_u64(req.secret_nullifier_hash));
    claim_bytes.extend_from_slice(&buyer);
    claim_bytes.extend_from_slice(&token);
    let claim_hash = keccak256(&claim_bytes);

    let mut message_bytes = Vec::with_capacity(23 + 32);
    message_bytes.extend_from_slice(b"trusted-stwo-message-v1");
    message_bytes.extend_from_slice(&claim_hash);
    let message_hash = keccak256(&message_bytes);

    let sig = state
        .signer
        .sign_digest(message_hash)
        .map_err(ApiError::Internal)?;

    Ok(Json(VerifyTlsnAndSignTransactionSettlementResponse {
        verified: true,
        comment_data,
        rev_tag,
        fiat_amount,
        transaction_id_hex: normalize_hex_prefixed(&req.transaction_id_hex),
        claim_hash_hex: format!("0x{}", hex::encode(claim_hash)),
        message_hash_hex: format!("0x{}", hex::encode(message_hash)),
        signature_hex: format!("0x{}", hex::encode(sig.signature_65)),
        signature_r_hex: format!("0x{}", hex::encode(sig.r)),
        signature_s_hex: format!("0x{}", hex::encode(sig.s)),
        signature_v: sig.v,
        signer_address: state.signer.address_hex(),
        signer_public_key_hex: state.signer.public_key_hex(),
        signed_at_unix: Utc::now().timestamp(),
    }))
}

fn normalize_hex_prefixed(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_lowercase()
    } else {
        format!("0x{}", s.to_lowercase())
    }
}

fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let clean = value.trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(clean)
        .map_err(|e| ApiError::InvalidInput(format!("invalid {field}: {e}")))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidInput(format!(
            "{field} must be 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_20(value: &str, field: &str) -> Result<[u8; 20], ApiError> {
    let clean = value.trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(clean)
        .map_err(|e| ApiError::InvalidInput(format!("invalid {field}: {e}")))?;
    if bytes.len() != 20 {
        return Err(ApiError::InvalidInput(format!(
            "{field} must be 20 bytes"
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn u256be_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(bytes);
    k.finalize(&mut out);
    out
}

fn parse_http_response(
    transcript: &str,
) -> Result<(String, HashMap<String, String>, String), ApiError> {
    let (head, raw_body) = transcript
        .split_once("\r\n\r\n")
        .or_else(|| transcript.split_once("\n\n"))
        .ok_or_else(|| ApiError::InvalidInput("invalid HTTP response transcript".to_string()))?;

    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| ApiError::InvalidInput("missing HTTP status line".to_string()))?
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }

    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false);

    let body = if is_chunked {
        decode_chunked_body(raw_body).map_err(|e| {
            ApiError::InvalidInput(format!("chunked body decode failed: {e}"))
        })?
    } else {
        raw_body.to_string()
    };

    Ok((status_line, headers, body))
}

fn decode_chunked_body(raw: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut remaining = raw;
    loop {
        let (size_line, after_size) = remaining
            .split_once("\r\n")
            .or_else(|| remaining.split_once('\n'))
            .ok_or_else(|| "missing chunk size line".to_string())?;
        // strip optional chunk extensions (e.g. "3e;ext=val" → "3e")
        let size_hex = size_line.trim().split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| format!("invalid chunk size '{size_hex}': {e}"))?;
        if chunk_size == 0 {
            break;
        }
        if after_size.len() < chunk_size {
            return Err(format!(
                "chunk data too short: expected {chunk_size} bytes, got {}",
                after_size.len()
            ));
        }
        result.push_str(&after_size[..chunk_size]);
        // skip exactly the \r\n (or \n) that follows the chunk data
        let tail = &after_size[chunk_size..];
        remaining = tail
            .strip_prefix("\r\n")
            .or_else(|| tail.strip_prefix('\n'))
            .unwrap_or(tail);
    }
    Ok(result)
}

fn sign_transfer_payload(
    comment_data: &str,
    rev_tag: &str,
    fiat_amount: u64,
    secret: &str,
) -> String {
    let payload = format!("{}|{}|{}|{}", comment_data, rev_tag, fiat_amount, secret);
    format!("0x{}", hex::encode(keccak256(payload.as_bytes())))
}
