use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use async_compat::Compat;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::offchain_merkle::OffchainMerkleTree;

use crate::config::AppState;

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    interface IPrivacyPool {
        function setVerifier(address verifier) external;
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
    }
}

const M31_MODULUS: u32 = 2_147_483_647;
const MERKLE_SIBLING_DEPTH: usize = 31;

pub fn address_to_m31(address: Address) -> u32 {
    let address_u256 = U256::from_be_slice(address.as_slice());
    let reduced = address_u256 % U256::from(M31_MODULUS);
    u32::try_from(reduced).expect("Address modulo M31 should fit into u32")
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
    let owner_private_key = app.owner_private_key.clone();
    let rpc_url = app.rpc_url.clone();
    let max_fee = app.max_fee_per_gas;
    let max_priority = app.max_priority_fee_per_gas;
    let label = label.to_string();

    Compat::new(async move {
        let signer: PrivateKeySigner = owner_private_key
            .parse()
            .map_err(|e| format!("Invalid private key: {e}"))?;
        let provider = ProviderBuilder::new().wallet(signer).connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let tx = TransactionRequest::default()
            .to(to)
            .input(input.into())
            .max_fee_per_gas(max_fee)
            .max_priority_fee_per_gas(max_priority);

        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("{label} send_transaction failed: {e}"))?;

        let receipt =
            tokio::time::timeout(std::time::Duration::from_secs(120), pending.get_receipt())
                .await
                .map_err(|_| format!("{label} get_receipt timed out after 120s"))?
                .map_err(|e| format!("{label} receipt failed: {e}"))?;

        if !receipt.status() {
            return Err(format!(
                "{label} transaction reverted, tx hash: {}, gas_used: {:?}",
                receipt.transaction_hash, receipt.gas_used
            ));
        }

        Ok(())
    })
    .await
}

pub async fn try_call_next_leaf_index(app: &AppState) -> Option<u64> {
    let data = IPrivacyPool::getNextLeafIndexCall {}.abi_encode();
    let raw = match run_eth_call(app, app.privacy_pool_address, data.into()).await {
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
    let raw = match run_eth_call(app, app.privacy_pool_address, data.into()).await {
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

async fn run_eth_call(app: &AppState, to: Address, input: Bytes) -> Result<Bytes, String> {
    let rpc_url = app.rpc_url.clone();

    Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );
        provider
            .call(TransactionRequest::default().to(to).input(input.into()))
            .await
            .map_err(|e| e.to_string())
    })
    .await
}
