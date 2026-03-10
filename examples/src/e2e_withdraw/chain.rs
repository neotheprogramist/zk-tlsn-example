use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol_types::SolCall,
};
use async_compat::Compat;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::offchain_merkle::OffchainMerkleTree;

use crate::common_rpc;
use super::{ANVIL_TOPUP_BALANCE_HEX, AppState, IERC20, IPrivacyPool};

const MERKLE_SIBLING_DEPTH: usize = 31;

pub async fn send_approve_tx(app: &AppState, amount: U256) -> Result<(), String> {
    let calldata = IERC20::approveCall {
        spender: app.privacy_pool_address,
        amount,
    }
    .abi_encode();
    send_simple_tx(app, app.withdraw_token, calldata.into(), "approve").await
}

pub async fn send_deposit_tx(
    app: &AppState,
    secret_nullifier_hash: U256,
    amount: U256,
) -> Result<(), String> {
    let calldata = IPrivacyPool::depositCall {
        secretNullifierHash: secret_nullifier_hash,
        amount,
        token: app.withdraw_token,
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
        app.withdraw_max_fee_per_gas,
        app.withdraw_max_priority_fee_per_gas,
        app.withdraw_gas_limit,
        to,
        input,
        label,
    )
    .await
}

pub fn address_to_m31(address: Address) -> u32 {
    common_rpc::address_to_m31(address)
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

pub async fn build_offchain_merkle_tree(app: &AppState) -> OffchainMerkleTree {
    let rpc_url = app.rpc_url.clone();
    let privacy_pool = app.privacy_pool_address;

    let logs = Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );
        let deposit_filter = Filter::new()
            .address(privacy_pool)
            .from_block(0u64)
            .event("Deposit(uint256,uint256,address,uint64,uint256)");
        let mut logs = provider
            .get_logs(&deposit_filter)
            .await
            .map_err(|e| format!("Failed to fetch deposit logs: {e}"))?;

        if logs.is_empty() {
            let leaf_filter = Filter::new()
                .address(privacy_pool)
                .from_block(0u64)
                .event("LeafAdded(address,uint256,uint256)");
            logs = provider
                .get_logs(&leaf_filter)
                .await
                .map_err(|e| format!("Failed to fetch leaf logs: {e}"))?;
        }

        Ok::<_, String>(logs)
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));

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
            .get(1)
            .unwrap_or_else(|| panic!("Deposit log missing indexed commitment topic"));
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256).unwrap_or_else(|_| {
            panic!("Deposit commitment does not fit u32/M31: {commitment_u256}")
        });
        tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }
    tree
}

pub async fn ensure_owner_has_eth_for_gas(app: &AppState) {
    common_rpc::ensure_owner_has_eth_for_gas(
        app.rpc_url.clone(),
        app.owner_private_key.clone(),
        ANVIL_TOPUP_BALANCE_HEX,
    )
    .await;
}
