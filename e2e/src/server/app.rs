use std::{collections::BTreeMap, sync::Arc};

use salvo::{
    Depot, Request, Response, Router, Writer, http::StatusCode, prelude::*, writing::Json,
};
use serde::{Deserialize, Serialize};
use shared::{FiatTransferAttestation, encode_transfer_attestation};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

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
    #[error("request decoding failed: {0}")]
    RequestDecode(#[from] salvo::http::ParseError),
    #[error("missing path param '{0}'")]
    MissingPathParam(&'static str),
    #[error(transparent)]
    Attestation(#[from] shared::AttestationError),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::UserNotFound(_) | Self::TransferNotFound(_) => StatusCode::NOT_FOUND,
            Self::UserAlreadyExists(_) => StatusCode::CONFLICT,
            Self::InvalidAmount
            | Self::InsufficientBalance { .. }
            | Self::InvalidConfig(_)
            | Self::RequestDecode(_)
            | Self::MissingPathParam(_)
            | Self::Attestation(_) => StatusCode::BAD_REQUEST,
        }
    }
}

#[async_trait]
impl Writer for ApiError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        res.status_code(self.status());
        res.render(self.to_string());
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
            ))?,
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

fn state(depot: &Depot) -> &AppState {
    depot
        .obtain::<AppState>()
        .expect("AppState must be injected by affix_state middleware")
}

pub fn get_app(config: AppConfig) -> Result<Router, ApiError> {
    Ok(build_router(AppState::new(config)?))
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .hoop(affix_state::inject(state))
        .push(Router::with_path("/api/config").get(get_config))
        .push(
            Router::with_path("/api/users")
                .get(list_users)
                .post(create_user),
        )
        .push(Router::with_path("/api/balance/{username}").get(get_balance))
        .push(Router::with_path("/api/transfers").post(create_transfer))
        .push(Router::with_path("/api/attestations/{tx_id}").get(get_attestation))
}

pub async fn seed_transfer_direct(
    state: &AppState,
    request: TransferRequest,
) -> Result<TransferResponse, ApiError> {
    state.ledger.write().await.transfer(request)
}

#[handler]
async fn get_config(depot: &mut Depot) -> Json<ServerConfigResponse> {
    info!("GET /api/config");
    let ledger = state(depot).ledger.read().await;
    Json(ledger.config())
}

#[handler]
async fn list_users(depot: &mut Depot) -> Json<Vec<UserResponse>> {
    info!("GET /api/users");
    let ledger = state(depot).ledger.read().await;
    Json(ledger.list_users())
}

#[handler]
async fn create_user(req: &mut Request, depot: &mut Depot) -> Result<Json<UserResponse>, ApiError> {
    let body: CreateUserRequest = req.parse_json().await?;
    info!(username = %body.username, balance = body.balance, "POST /api/users");
    let mut ledger = state(depot).ledger.write().await;
    ledger
        .register_user(body.username, body.balance)
        .inspect(|resp| info!(user_id = resp.id, "User created"))
        .inspect_err(|e| warn!(error = %e, "User creation rejected"))
        .map(Json)
}

#[handler]
async fn get_balance(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<BalanceResponse>, ApiError> {
    let username: String = req
        .param("username")
        .ok_or(ApiError::MissingPathParam("username"))?;
    info!(username = %username, "GET /api/balance");
    let ledger = state(depot).ledger.read().await;
    ledger.balance(&username).map(Json)
}

#[handler]
async fn create_transfer(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<TransferResponse>, ApiError> {
    let body: TransferRequest = req.parse_json().await?;
    info!(
        from = %body.from_username,
        to = %body.to_username,
        amount = body.amount,
        "POST /api/transfers"
    );
    let mut ledger = state(depot).ledger.write().await;
    ledger
        .transfer(body)
        .inspect(|resp| info!(tx_id = resp.tx_id, "Transfer created"))
        .inspect_err(|e| warn!(error = %e, "Transfer rejected"))
        .map(Json)
}

#[handler]
async fn get_attestation(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<TransferResponse>, ApiError> {
    let tx_id: u64 = req
        .param("tx_id")
        .ok_or(ApiError::MissingPathParam("tx_id"))?;
    info!(tx_id, "GET /api/attestations");
    let ledger = state(depot).ledger.read().await;
    ledger
        .attestation(tx_id)
        .inspect_err(|e| warn!(tx_id, error = %e, "Attestation lookup failed"))
        .map(Json)
}
