use std::{collections::HashMap, sync::Arc};

use async_compat::CompatExt;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use smol::lock::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("User '{0}' not found")]
    UserNotFound(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::UserNotFound(username) => (
                StatusCode::NOT_FOUND,
                format!("User '{}' not found", username),
            ),
        };
        (status, message).into_response()
    }
}

#[derive(Clone)]
pub struct AppState {
    balances: Arc<RwLock<HashMap<String, u64>>>,
    rev_tag: String,
    fiat_amount: u64,
    signature_secret: String,
}

impl AppState {
    pub fn new(balances: HashMap<String, u64>) -> Self {
        let rev_tag = std::env::var("MOCK_REV_TAG").unwrap_or_else(|_| "@alice".to_string());
        let fiat_amount = std::env::var("MOCK_FIAT_AMOUNT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(123);
        let signature_secret =
            std::env::var("MOCK_SIGNATURE_SECRET").unwrap_or_else(|_| "mock-secret".to_string());
        Self {
            balances: Arc::new(RwLock::new(balances)),
            rev_tag,
            fiat_amount,
            signature_secret,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BalanceResponse {
    username: String,
    balance: u64,
    #[serde(rename = "z")]
    padding: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferResponse {
    #[serde(rename = "commentData")]
    comment_data: String,
    #[serde(rename = "revTag")]
    rev_tag: String,
    #[serde(rename = "fiatAmount")]
    fiat_amount: u64,
    #[serde(rename = "z")]
    padding: String,
}

impl TransferResponse {
    fn new(comment_data: String, rev_tag: String, fiat_amount: u64) -> Self {
        Self {
            comment_data,
            rev_tag,
            fiat_amount,
            padding: " ".repeat(12),
        }
    }
}

impl BalanceResponse {
    fn new(username: String, balance: u64) -> Self {
        Self {
            username,
            balance,
            padding: " ".repeat(12),
        }
    }
}

pub fn get_app(balances: HashMap<String, u64>) -> Router {
    let state = AppState::new(balances);
    Router::new()
        .route("/api/balance/{username}", get(get_balance))
    .route("/api/transfer/{comment}", get(get_transfer))
        .with_state(state)
}

async fn get_balance(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let balances = state.balances.read().compat().await;

    match balances.get(&username) {
        Some(&balance) => Ok(Json(BalanceResponse::new(username, balance))),
        None => Err(ApiError::UserNotFound(username)),
    }
}

async fn get_transfer(
    State(state): State<AppState>,
    Path(comment): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let body = TransferResponse::new(comment, state.rev_tag.clone(), state.fiat_amount);
    let signature = sign_transfer_payload(
        &body.comment_data,
        &body.rev_tag,
        body.fiat_amount,
        &state.signature_secret,
    );

    Ok((
        [("x-revolut-signature", signature)],
        Json(body),
    ))
}

fn sign_transfer_payload(
    comment_data: &str,
    rev_tag: &str,
    fiat_amount: u64,
    secret: &str,
) -> String {
    use tiny_keccak::{Hasher, Keccak};

    let payload = format!("{}|{}|{}|{}", comment_data, rev_tag, fiat_amount, secret);
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(payload.as_bytes());
    k.finalize(&mut out);
    format!("0x{}", hex::encode(out))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn test_get_balance_existing_user() {
        smol::block_on(async {
            let mut balances = HashMap::new();
            balances.insert("alice".to_string(), 100);
            balances.insert("bob".to_string(), 250);

            let app = get_app(balances);

            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/balance/alice")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let balance_response: BalanceResponse = serde_json::from_slice(&body).unwrap();

            assert_eq!(balance_response.username, "alice");
            assert_eq!(balance_response.balance, 100);
        });
    }

    #[test]
    fn test_get_balance_nonexistent_user() {
        smol::block_on(async {
            let balances = HashMap::new();
            let app = get_app(balances);

            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/balance/charlie")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn test_get_transfer_contains_expected_fields_and_signature() {
        smol::block_on(async {
            let app = get_app(HashMap::new());
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/transfer/cmt-123")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers().get("x-revolut-signature").is_some());

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let parsed: TransferResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed.comment_data, "cmt-123");
            assert_eq!(parsed.rev_tag, "@alice");
            assert_eq!(parsed.fiat_amount, 123);
        });
    }
}
