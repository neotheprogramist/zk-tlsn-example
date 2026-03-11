use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::SolCall,
};
use async_compat::Compat;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::offchain_merkle::OffchainMerkleTree;

use crate::common_rpc;
use super::config::AppState;

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    interface IPrivacyPool {
        function setVerifier(address verifier) external;
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function createOffer(
            uint256 root,
            uint256 nullifier,
            address token,
            uint256 amount,
            uint256 refundCommitmentHash,
            uint256 secretHash,
            string calldata currency,
            uint256 fiatAmount,
            string calldata revTag,
            bytes calldata verifyCalldata
        ) external;
        function cancelIntent(
            uint256 offerSecret,
            uint256 cancelHash
        ) external;
        function cancelClaim(
            uint256 offerHash,
            uint256 cancelSecret,
            uint256 secretNullifierHash
        ) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
    }
}

const MERKLE_SIBLING_DEPTH: usize = 31;

pub fn address_to_m31(address: Address) -> u32 {
    common_rpc::address_to_m31(address)
}

pub async fn send_approve_tx(app: &AppState, amount: U256) -> Result<(), String> {
    let calldata = IERC20::approveCall {
        spender: app.privacy_pool_address,
        amount,
    }
    .abi_encode();
    send_simple_tx(app, app.token_address, calldata.into(), "approve").await
}

pub async fn send_deposit_tx(
    app: &AppState,
    secret_nullifier_hash: U256,
    amount: U256,
) -> Result<(), String> {
    let calldata = IPrivacyPool::depositCall {
        secretNullifierHash: secret_nullifier_hash,
        amount,
        token: app.token_address,
    }
    .abi_encode();
    send_simple_tx(app, app.privacy_pool_address, calldata.into(), "deposit").await
}

async fn send_simple_tx(
    app: &AppState,
    to: Address,
    input: Bytes,
    label: &str,
) -> Result<(), String> {
    common_rpc::send_simple_tx(
        app.rpc_url.clone(),
        app.owner_private_key.clone(),
        app.max_fee_per_gas,
        app.max_priority_fee_per_gas,
        app.gas_limit,
        to,
        input,
        label,
    )
    .await
}

pub async fn try_call_next_leaf_index(app: &AppState) -> Option<u64> {
    let data = IPrivacyPool::getNextLeafIndexCall {}.abi_encode();
    let raw = match common_rpc::run_eth_call(app.rpc_url.clone(), app.privacy_pool_address, data.into()).await {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(err = %e, "getNextLeafIndex eth_call failed");
            return None;
        }
    };

    match IPrivacyPool::getNextLeafIndexCall::abi_decode_returns(&raw) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!(
                err = %e,
                raw_len = raw.len(),
                raw = %alloy::hex::encode(raw.as_ref()),
                "Failed to decode getNextLeafIndex return"
            );
            None
        }
    }
}

pub async fn try_call_current_root(app: &AppState) -> Option<U256> {
    let data = IPrivacyPool::getCurrentRootCall {}.abi_encode();
    let raw = match common_rpc::run_eth_call(app.rpc_url.clone(), app.privacy_pool_address, data.into()).await {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(err = %e, "getCurrentRoot eth_call failed");
            return None;
        }
    };

    match IPrivacyPool::getCurrentRootCall::abi_decode_returns(&raw) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!(
                err = %e,
                raw_len = raw.len(),
                raw = %alloy::hex::encode(raw.as_ref()),
                "Failed to decode getCurrentRoot return"
            );
            None
        }
    }
}

pub async fn build_offchain_merkle_tree(app: &AppState) -> Result<OffchainMerkleTree, String> {
    let rpc_url = app.rpc_url.clone();
    let privacy_pool = app.privacy_pool_address;

    let logs = Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let leaf_filter = Filter::new()
            .address(privacy_pool)
            .from_block(0u64)
            .event("LeafAdded(address,uint256,uint256)");

        provider
            .get_logs(&leaf_filter)
            .await
            .map_err(|e| format!("Failed to fetch LeafAdded logs: {e}"))
    })
    .await?;

    let mut sorted_logs = logs;
    sorted_logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });

    let mut tree = OffchainMerkleTree::new(MERKLE_SIBLING_DEPTH);
    for log in sorted_logs {
        let commitment_topic = log
            .inner
            .topics()
            .get(2)
            .ok_or_else(|| "LeafAdded log missing indexed commitment topic".to_string())?;
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256)
            .map_err(|_| format!("LeafAdded commitment does not fit u32/M31: {commitment_u256}"))?;
        tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }

    Ok(tree)
}

pub async fn send_create_offer_tx(
    app: &AppState,
    root: U256,
    nullifier: U256,
    token: Address,
    amount: U256,
    refund_commitment_hash: U256,
    secret_hash: U256,
    currency: String,
    fiat_amount: U256,
    rev_tag: String,
    verify_calldata: Bytes,
) -> Result<(), String> {
    let calldata = IPrivacyPool::createOfferCall {
        root,
        nullifier,
        token,
        amount,
        refundCommitmentHash: refund_commitment_hash,
        secretHash: secret_hash,
        currency,
        fiatAmount: fiat_amount,
        revTag: rev_tag,
        verifyCalldata: verify_calldata,
    }
    .abi_encode();
    
    send_simple_tx(app, app.privacy_pool_address, calldata.into(), "createOffer").await
}

pub async fn send_cancel_intent_tx(
    app: &AppState,
    offer_secret: U256,
    cancel_hash: U256,
) -> Result<(), String> {
    let calldata = IPrivacyPool::cancelIntentCall {
        offerSecret: offer_secret,
        cancelHash: cancel_hash,
    }
    .abi_encode();
    
    send_simple_tx(app, app.privacy_pool_address, calldata.into(), "cancelIntent").await
}

pub async fn send_cancel_claim_tx(
    app: &AppState,
    offer_hash: U256,
    cancel_secret: U256,
    secret_nullifier_hash: U256,
) -> Result<(), String> {
    let calldata = IPrivacyPool::cancelClaimCall {
        offerHash: offer_hash,
        cancelSecret: cancel_secret,
        secretNullifierHash: secret_nullifier_hash,
    }
    .abi_encode();
    
    send_simple_tx(app, app.privacy_pool_address, calldata.into(), "cancelClaim").await
}
