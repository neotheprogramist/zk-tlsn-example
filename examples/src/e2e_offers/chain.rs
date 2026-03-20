use alloy::primitives::{Address, U256};
use stwo_circuit::onchain::OnchainVerificationInput;

use crate::common_rpc;
use super::config::AppState;

pub async fn send_create_offer_tx(
    app: &AppState,
    root: U256,
    nullifier: U256,
    token: Address,
    amount: U256,
    offer_commitment: U256,
    refund_commitment_hash: U256,
    secret_hash: U256,
    currency: String,
    fiat_amount: U256,
    rev_tag: String,
    verify_input: &OnchainVerificationInput,
) -> Result<(), String> {
    let calldata = stwo_circuit::build_create_offer_calldata(
        root, nullifier, token, amount, offer_commitment, refund_commitment_hash,
        secret_hash, currency, fiat_amount, rev_tag, verify_input,
    );
    common_rpc::send_simple_tx(
        app.rpc_url.clone(), app.owner_private_key.clone(),
        app.max_fee_per_gas, app.max_priority_fee_per_gas, app.gas_limit,
        app.privacy_pool_address, calldata.into(), "createOffer",
    ).await
}

pub async fn send_cancel_intent_tx(app: &AppState, offer_secret: U256, cancel_hash: U256) -> Result<(), String> {
    use alloy::{sol, sol_types::SolCall};
    sol! {
        interface IPrivacyPool {
            function cancelIntent(uint256 offerSecret, uint256 cancelHash) external;
        }
    }
    let calldata = IPrivacyPool::cancelIntentCall { offerSecret: offer_secret, cancelHash: cancel_hash }.abi_encode();
    common_rpc::send_simple_tx(
        app.rpc_url.clone(), app.owner_private_key.clone(),
        app.max_fee_per_gas, app.max_priority_fee_per_gas, app.gas_limit,
        app.privacy_pool_address, calldata.into(), "cancelIntent",
    ).await
}

pub async fn send_cancel_claim_tx(app: &AppState, offer_hash: U256, cancel_secret: U256, secret_nullifier_hash: U256) -> Result<(), String> {
    use alloy::{sol, sol_types::SolCall};
    sol! {
        interface IPrivacyPool2 {
            function cancelClaim(uint256 offerHash, uint256 cancelSecret, uint256 secretNullifierHash) external;
        }
    }
    let calldata = IPrivacyPool2::cancelClaimCall {
        offerHash: offer_hash, cancelSecret: cancel_secret, secretNullifierHash: secret_nullifier_hash,
    }.abi_encode();
    common_rpc::send_simple_tx(
        app.rpc_url.clone(), app.owner_private_key.clone(),
        app.max_fee_per_gas, app.max_priority_fee_per_gas, app.gas_limit,
        app.privacy_pool_address, calldata.into(), "cancelClaim",
    ).await
}
