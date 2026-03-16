use std::{collections::BTreeMap, sync::Arc};

use async_compat::CompatExt;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use shared::{FiatTransferAttestation, encode_transfer_attestation};
use smol::lock::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("user '{0}' not found")]
    UserNotFound(String),
    #[error("user '{0}' already exists")]
    UserAlreadyExists(String),
    #[error("transfer '{0}' not found")]
    TransferNotFound(u64),
    #[error("amount must be greater than zero")]
    InvalidAmount,
    #[error("insufficient balance for '{username}': have {available}, need {required}")]
    InsufficientBalance {
        username: String,
        available: u64,
        required: u64,
    },
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::UserNotFound(_) | Self::TransferNotFound(_) => StatusCode::NOT_FOUND,
            Self::UserAlreadyExists(_) => StatusCode::CONFLICT,
            Self::InvalidAmount | Self::InsufficientBalance { .. } | Self::InvalidConfig(_) => {
                StatusCode::BAD_REQUEST
            }
        };

        (status, self.to_string()).into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InitialUser {
    pub username: String,
    pub balance: u64,
}

impl InitialUser {
    #[must_use]
    pub fn new(username: impl Into<String>, balance: u64) -> Self {
        Self {
            username: username.into(),
            balance,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub users: Vec<InitialUser>,
    pub special_username: String,
}

impl AppConfig {
    #[must_use]
    pub fn demo_defaults() -> Self {
        Self {
            users: vec![
                InitialUser::new("alice", 100),
                InitialUser::new("bob", 40),
                InitialUser::new("treasury", 0),
            ],
            special_username: String::from("treasury"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: u64,
    pub username: String,
    pub balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub id: u64,
    pub username: String,
    pub balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    pub username: String,
    pub balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    pub from_username: String,
    pub to_username: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransferResponse {
    pub tx_id: u64,
    pub from_user_id: u64,
    pub from_username: String,
    pub to_user_id: u64,
    pub to_username: String,
    pub amount: u64,
    pub attestation: String,
    pub eligible_for_mint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfigResponse {
    pub special_user_id: u64,
    pub special_username: String,
}

#[derive(Debug, Clone)]
struct User {
    id: u64,
    username: String,
    balance: u64,
}

impl From<&User> for UserResponse {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            balance: user.balance,
        }
    }
}

impl From<&User> for BalanceResponse {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            balance: user.balance,
        }
    }
}

#[derive(Debug, Clone)]
struct Transfer {
    tx_id: u64,
    from_user_id: u64,
    from_username: String,
    to_user_id: u64,
    to_username: String,
    amount: u64,
    attestation: String,
}

impl Transfer {
    fn response(&self, special_user_id: u64) -> TransferResponse {
        TransferResponse {
            tx_id: self.tx_id,
            from_user_id: self.from_user_id,
            from_username: self.from_username.clone(),
            to_user_id: self.to_user_id,
            to_username: self.to_username.clone(),
            amount: self.amount,
            attestation: self.attestation.clone(),
            eligible_for_mint: self.to_user_id == special_user_id,
        }
    }
}

#[derive(Debug)]
struct Ledger {
    users_by_name: BTreeMap<String, User>,
    transfers_by_id: BTreeMap<u64, Transfer>,
    next_user_id: u64,
    next_tx_id: u64,
    special_user_id: u64,
    special_username: String,
}

impl Ledger {
    fn new(config: AppConfig) -> Result<Self, ApiError> {
        let mut ledger = Self {
            users_by_name: BTreeMap::new(),
            transfers_by_id: BTreeMap::new(),
            next_user_id: 1,
            next_tx_id: 1,
            special_user_id: 0,
            special_username: config.special_username.clone(),
        };

        config.users.into_iter().try_for_each(|user| {
            ledger
                .register_user(user.username, user.balance)
                .map(|_| ())
        })?;

        if !ledger.users_by_name.contains_key(&config.special_username) {
            ledger.register_user(config.special_username.clone(), 0)?;
        }

        ledger.special_user_id = ledger
            .users_by_name
            .get(&config.special_username)
            .map(|user| user.id)
            .ok_or_else(|| {
                ApiError::InvalidConfig(format!(
                    "special user '{}' could not be resolved",
                    config.special_username
                ))
            })?;

        Ok(ledger)
    }

    fn register_user(&mut self, username: String, balance: u64) -> Result<UserResponse, ApiError> {
        if self.users_by_name.contains_key(&username) {
            return Err(ApiError::UserAlreadyExists(username));
        }

        let user = User {
            id: self.next_user_id,
            username: username.clone(),
            balance,
        };
        let response = UserResponse::from(&user);
        self.next_user_id = self
            .next_user_id
            .checked_add(1)
            .ok_or_else(|| ApiError::InvalidConfig(String::from("user id overflow")))?;
        self.users_by_name.insert(username, user);

        Ok(response)
    }

    fn list_users(&self) -> Vec<UserResponse> {
        self.users_by_name
            .values()
            .map(UserResponse::from)
            .collect()
    }

    fn balance(&self, username: &str) -> Result<BalanceResponse, ApiError> {
        self.users_by_name
            .get(username)
            .map(BalanceResponse::from)
            .ok_or_else(|| ApiError::UserNotFound(String::from(username)))
    }

    fn config(&self) -> ServerConfigResponse {
        ServerConfigResponse {
            special_user_id: self.special_user_id,
            special_username: self.special_username.clone(),
        }
    }

    fn transfer(&mut self, request: TransferRequest) -> Result<TransferResponse, ApiError> {
        if request.amount == 0 {
            return Err(ApiError::InvalidAmount);
        }

        let from_user = self
            .users_by_name
            .get(&request.from_username)
            .cloned()
            .ok_or_else(|| ApiError::UserNotFound(request.from_username.clone()))?;
        let to_user = self
            .users_by_name
            .get(&request.to_username)
            .cloned()
            .ok_or_else(|| ApiError::UserNotFound(request.to_username.clone()))?;

        if from_user.balance < request.amount {
            return Err(ApiError::InsufficientBalance {
                username: from_user.username,
                available: from_user.balance,
                required: request.amount,
            });
        }

        self.update_balance(&request.from_username, from_user.balance - request.amount)?;
        self.update_balance(
            &request.to_username,
            to_user.balance.checked_add(request.amount).ok_or_else(|| {
                ApiError::InvalidConfig(String::from("recipient balance overflow"))
            })?,
        )?;

        let tx_id = self.next_tx_id;
        self.next_tx_id = self
            .next_tx_id
            .checked_add(1)
            .ok_or_else(|| ApiError::InvalidConfig(String::from("transfer id overflow")))?;
        let transfer = Transfer {
            tx_id,
            from_user_id: from_user.id,
            from_username: from_user.username,
            to_user_id: to_user.id,
            to_username: to_user.username,
            amount: request.amount,
            attestation: encode_transfer_attestation(FiatTransferAttestation::new(
                tx_id,
                to_user.id,
                request.amount,
            ))
            .map_err(|error| ApiError::InvalidConfig(error.to_string()))?,
        };
        let response = transfer.response(self.special_user_id);
        self.transfers_by_id.insert(tx_id, transfer);
        Ok(response)
    }

    fn attestation(&self, tx_id: u64) -> Result<TransferResponse, ApiError> {
        self.transfers_by_id
            .get(&tx_id)
            .map(|transfer| transfer.response(self.special_user_id))
            .ok_or(ApiError::TransferNotFound(tx_id))
    }

    fn update_balance(&mut self, username: &str, balance: u64) -> Result<(), ApiError> {
        self.users_by_name
            .get_mut(username)
            .map(|user| {
                user.balance = balance;
            })
            .ok_or_else(|| ApiError::UserNotFound(String::from(username)))
    }
}

#[derive(Clone)]
pub struct AppState {
    ledger: Arc<RwLock<Ledger>>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, ApiError> {
        Ok(Self {
            ledger: Arc::new(RwLock::new(Ledger::new(config)?)),
        })
    }
}

pub fn get_app(config: AppConfig) -> Result<Router, ApiError> {
    let state = AppState::new(config)?;

    Ok(Router::new()
        .route("/api/config", get(get_config))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/balance/{username}", get(get_balance))
        .route("/api/transfers", post(create_transfer))
        .route("/api/attestations/{tx_id}", get(get_attestation))
        .with_state(state))
}

async fn get_config(State(state): State<AppState>) -> Json<ServerConfigResponse> {
    let ledger = state.ledger.read().compat().await;
    Json(ledger.config())
}

async fn list_users(State(state): State<AppState>) -> Json<Vec<UserResponse>> {
    let ledger = state.ledger.read().compat().await;
    Json(ledger.list_users())
}

async fn create_user(
    State(state): State<AppState>,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let mut ledger = state.ledger.write().compat().await;
    ledger
        .register_user(request.username, request.balance)
        .map(Json)
}

async fn get_balance(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let ledger = state.ledger.read().compat().await;
    ledger.balance(&username).map(Json)
}

async fn create_transfer(
    State(state): State<AppState>,
    Json(request): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, ApiError> {
    let mut ledger = state.ledger.write().compat().await;
    ledger.transfer(request).map(Json)
}

async fn get_attestation(
    State(state): State<AppState>,
    Path(tx_id): Path<u64>,
) -> Result<Json<TransferResponse>, ApiError> {
    let ledger = state.ledger.read().compat().await;
    ledger.attestation(tx_id).map(Json)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn test_config() -> AppConfig {
        AppConfig {
            users: vec![
                InitialUser::new("alice", 100),
                InitialUser::new("treasury", 0),
            ],
            special_username: String::from("treasury"),
        }
    }

    #[test]
    fn test_get_balance_existing_user() {
        smol::block_on(async {
            let app = get_app(test_config()).expect("app");

            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/balance/alice")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::OK);

            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let balance: BalanceResponse = serde_json::from_slice(&body).expect("balance response");

            assert_eq!(balance.username, "alice");
            assert_eq!(balance.balance, 100);
        });
    }

    #[test]
    fn test_create_user_registers_balance() {
        smol::block_on(async {
            let app = get_app(test_config()).expect("app");
            let request = CreateUserRequest {
                username: String::from("bob"),
                balance: 25,
            };

            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/users")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("request json"),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_transfer_creates_attestation_and_updates_balances() {
        smol::block_on(async {
            let app = get_app(test_config()).expect("app");
            let request = TransferRequest {
                from_username: String::from("alice"),
                to_username: String::from("treasury"),
                amount: 25,
            };

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/transfers")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("request json"),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::OK);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let transfer: TransferResponse =
                serde_json::from_slice(&body).expect("transfer response");
            assert_eq!(transfer.tx_id, 1);
            assert!(transfer.eligible_for_mint);
            assert_eq!(transfer.attestation.len(), 32);

            let balance_response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/balance/alice")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let balance_body = balance_response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let balance: BalanceResponse =
                serde_json::from_slice(&balance_body).expect("balance response");
            assert_eq!(balance.balance, 75);
        });
    }

    #[test]
    fn test_transfer_rejects_insufficient_balance() {
        smol::block_on(async {
            let app = get_app(test_config()).expect("app");
            let request = TransferRequest {
                from_username: String::from("alice"),
                to_username: String::from("treasury"),
                amount: 101,
            };

            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/transfers")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("request json"),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn test_get_attestation_returns_non_special_transfer_for_negative_cases() {
        smol::block_on(async {
            let app = get_app(AppConfig {
                users: vec![
                    InitialUser::new("alice", 100),
                    InitialUser::new("bob", 0),
                    InitialUser::new("treasury", 0),
                ],
                special_username: String::from("treasury"),
            })
            .expect("app");
            let request = TransferRequest {
                from_username: String::from("alice"),
                to_username: String::from("bob"),
                amount: 20,
            };

            let transfer_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/transfers")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("request json"),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response");
            let transfer_body = transfer_response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let transfer: TransferResponse =
                serde_json::from_slice(&transfer_body).expect("transfer response");

            let response = app
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/attestations/{}", transfer.tx_id))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::OK);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let attestation: TransferResponse =
                serde_json::from_slice(&body).expect("attestation response");
            assert!(!attestation.eligible_for_mint);
            assert_eq!(attestation.to_username, "bob");
        });
    }
}
