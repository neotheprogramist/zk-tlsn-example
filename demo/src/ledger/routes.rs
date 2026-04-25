use salvo::{Depot, Request, handler, writing::Json};
use tracing::{info, warn};

use super::{
    ApiError, AppState, BalanceResponse, CreateUserRequest, ServerConfigResponse, TransferRequest,
    TransferResponse, UserResponse,
};

fn state(depot: &Depot) -> &AppState {
    depot
        .obtain::<AppState>()
        .expect("AppState must be injected by affix_state middleware")
}

#[handler]
pub(super) async fn get_config(depot: &mut Depot) -> Json<ServerConfigResponse> {
    info!("GET /api/config");
    let ledger = state(depot).ledger.read().await;
    Json(ledger.config())
}

#[handler]
pub(super) async fn list_users(depot: &mut Depot) -> Json<Vec<UserResponse>> {
    info!("GET /api/users");
    let ledger = state(depot).ledger.read().await;
    Json(ledger.list_users())
}

#[handler]
pub(super) async fn create_user(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<UserResponse>, ApiError> {
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
pub(super) async fn get_balance(
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
pub(super) async fn create_transfer(
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
pub(super) async fn get_attestation(
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
