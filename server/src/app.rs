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
}

impl AppState {
    pub fn new(balances: HashMap<String, u64>) -> Self {
        Self {
            balances: Arc::new(RwLock::new(balances)),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BalanceResponse {
    username: String,
    balance: u64,
}

pub fn get_app(balances: HashMap<String, u64>) -> Router {
    let state = AppState::new(balances);
    Router::new()
        .route("/api/balance/{username}", get(get_balance))
        .with_state(state)
}

async fn get_balance(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let balances = state.balances.read().compat().await;

    match balances.get(&username) {
        Some(&balance) => Ok(Json(BalanceResponse { username, balance })),
        None => Err(ApiError::UserNotFound(username)),
    }
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
}
