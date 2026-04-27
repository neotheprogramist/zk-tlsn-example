use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use salvo::{
    Depot, Request, Response, Router, Service, Writer, async_trait,
    conn::SocketAddr as SalvoSocketAddr,
    handler,
    http::{StatusCode, uri::Scheme},
    prelude::*,
    writing::Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use zktlsn_core::{FiatTransferAttestation, encode_transfer_attestation};

use crate::tls::get_or_create_test_tls_config;

// ─── Listener ──────────────────────────────────────────────────────────────

pub struct DemoServerConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Error)]
enum ConnectionError {
    #[error(transparent)]
    TlsHandshake(#[from] std::io::Error),

    #[error(transparent)]
    ServeConnection(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub async fn serve(cfg: DemoServerConfig, state: AppState) -> Result<()> {
    let tls = get_or_create_test_tls_config(&cfg.cert_path, &cfg.key_path)
        .context("failed to load or create TLS server configuration")?;
    let server_config = tls.server_config;
    let router = build_router(state);
    let service = Arc::new(Service::new(router));
    let listener = TcpListener::bind(cfg.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen_addr))?;

    tracing::info!(listen_addr = %cfg.listen_addr, "TLS demo server listening");

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("failed to accept connection")?;
        let service = Arc::clone(&service);
        let server_config = server_config.clone();

        tracing::info!(%addr, "Accepted connection");
        tokio::spawn(async move {
            if let Err(error) = handle_connection(service, server_config, stream).await {
                tracing::error!(error = %error, "Connection error");
            }
        });
    }
}

async fn handle_connection(
    service: Arc<Service>,
    server_config: Arc<rustls::ServerConfig>,
    cnx: TcpStream,
) -> Result<(), ConnectionError> {
    let stream = TlsAcceptor::from(server_config).accept(cnx).await?;
    let hyper_handler = service.hyper_handler(
        SalvoSocketAddr::Unknown,
        SalvoSocketAddr::Unknown,
        Scheme::HTTPS,
        None,
        None,
    );
    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), hyper_handler)
        .await?;
    Ok(())
}

// ─── API errors ────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("user '{0}' not found")]
    UserNotFound(String),
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
    #[error("missing path param '{0}'")]
    MissingPathParam(&'static str),
    #[error(transparent)]
    Attestation(#[from] zktlsn_core::Error),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::UserNotFound(_) | Self::TransferNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidAmount
            | Self::InsufficientBalance { .. }
            | Self::InvalidConfig(_)
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

// ─── API types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
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

// ─── Ledger ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct User {
    id: u64,
    username: String,
    balance: u64,
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
pub(crate) struct Ledger {
    users_by_name: BTreeMap<String, User>,
    transfers_by_id: BTreeMap<u64, Transfer>,
    next_user_id: u64,
    next_tx_id: u64,
    special_user_id: u64,
}

impl Ledger {
    fn new(config: AppConfig) -> Result<Self, ApiError> {
        let mut ledger = Self {
            users_by_name: BTreeMap::new(),
            transfers_by_id: BTreeMap::new(),
            next_user_id: 1,
            next_tx_id: 1,
            special_user_id: 0,
        };

        config
            .users
            .into_iter()
            .try_for_each(|user| ledger.register_user(user.username, user.balance))?;

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

    fn register_user(&mut self, username: String, balance: u64) -> Result<(), ApiError> {
        if self.users_by_name.contains_key(&username) {
            return Err(ApiError::InvalidConfig(format!(
                "duplicate user '{username}'"
            )));
        }

        let user = User {
            id: self.next_user_id,
            username: username.clone(),
            balance,
        };
        self.next_user_id = self
            .next_user_id
            .checked_add(1)
            .ok_or_else(|| ApiError::InvalidConfig(String::from("user id overflow")))?;
        self.users_by_name.insert(username, user);
        Ok(())
    }

    pub(crate) fn transfer(
        &mut self,
        request: TransferRequest,
    ) -> Result<TransferResponse, ApiError> {
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

    pub(crate) fn attestation(&self, tx_id: u64) -> Result<TransferResponse, ApiError> {
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

// ─── App ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub(crate) ledger: Arc<RwLock<Ledger>>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, ApiError> {
        Ok(Self {
            ledger: Arc::new(RwLock::new(Ledger::new(config)?)),
        })
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .hoop(affix_state::inject(state))
        .push(Router::with_path("/api/attestations/{tx_id}").get(get_attestation))
}

pub async fn seed_transfer(
    state: &AppState,
    request: TransferRequest,
) -> Result<TransferResponse, ApiError> {
    state.ledger.write().await.transfer(request)
}

// ─── Route handlers ────────────────────────────────────────────────────────

fn state(depot: &Depot) -> &AppState {
    depot
        .obtain::<AppState>()
        .expect("AppState must be injected by affix_state middleware")
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
