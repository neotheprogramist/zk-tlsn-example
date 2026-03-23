use alloy::{
    hex,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder, ext::AnvilApi},
    rpc::types::{Filter, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use async_compat::Compat;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::offchain_merkle::OffchainMerkleTree;

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    interface IPrivacyPoolCommon {
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
    }
}

pub async fn build_offchain_offers_tree(rpc_url: String, privacy_pool: Address) -> OffchainMerkleTree {
    let logs = Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url.parse().map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );
        // OfferCreated(uint256 indexed secretHash, string indexed offerType, uint256 offerCommitment, ...)
        let filter = Filter::new()
            .address(privacy_pool)
            .from_block(0u64)
            .event("OfferCreated(uint256,string,uint256,uint256,uint256,uint256,string,address,string)");
        provider
            .get_logs(&filter)
            .await
            .map_err(|e| format!("Failed to fetch OfferCreated logs: {e}"))
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

    // offerCommitment is the 1st non-indexed field (after 2 indexed topics + topic[0]=event sig)
    // topics: [0]=sig, [1]=secretHash, [2]=offerType(indexed string=keccak)
    // data: offerCommitment (uint256), refundCommitment (uint256), cryptoAmount, fiatAmount, ...
    let mut tree = OffchainMerkleTree::new(MERKLE_SIBLING_DEPTH);
    for log in sorted_logs {
        let data = log.inner.data.data.as_ref();
        if data.len() < 32 {
            panic!("OfferCreated log data too short");
        }
        let commitment_u256 = U256::from_be_slice(&data[0..32]);
        let commitment_u32 = u32::try_from(commitment_u256).unwrap_or_else(|_| {
            panic!("OfferCreated offerCommitment does not fit u32/M31: {commitment_u256}")
        });
        tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }
    tree
}

const MERKLE_SIBLING_DEPTH: usize = 31;

pub const M31_MODULUS: u32 = 2_147_483_647;

pub fn address_to_m31(address: Address) -> BaseField {
    let address_u256 = U256::from_be_slice(address.as_slice());
    let reduced = address_u256 % U256::from(M31_MODULUS);
    let reduced_u32 = u32::try_from(reduced).unwrap_or_else(|_| {
        panic!("Address modulo M31 should fit into u32: {reduced}")
    });
    BaseField::from_u32_unchecked(reduced_u32)
}

pub fn string_to_m31(s: &str) -> BaseField {
    let hash = alloy::primitives::keccak256(s.as_bytes());
    let value = u32::from_le_bytes(hash[..4].try_into().expect("4 bytes")) % M31_MODULUS;
    BaseField::from_u32_unchecked(value)
}

pub async fn send_simple_tx(
    rpc_url: String,
    owner_private_key: String,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    gas_limit: u64,
    to: Address,
    input: Bytes,
    label: &str,
) -> Result<(), String> {
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
            .max_fee_per_gas(max_fee_per_gas)
            .max_priority_fee_per_gas(max_priority_fee_per_gas)
            .gas_limit(gas_limit);

        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("{label} send_transaction failed: {e}"))?;

        let receipt = tokio::time::timeout(std::time::Duration::from_secs(120), pending.get_receipt())
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

pub async fn run_eth_call(rpc_url: String, to: Address, input: Bytes) -> Result<Bytes, String> {
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

pub async fn get_erc20_balance(rpc_url: String, token: Address, account: Address) -> U256 {
    let data = IERC20::balanceOfCall { account }.abi_encode();
    let raw = run_eth_call(rpc_url, token, data.into())
        .await
        .unwrap_or_else(|e| panic!("balanceOf eth_call failed: {e}"));
    IERC20::balanceOfCall::abi_decode_returns(&raw)
        .unwrap_or_else(|e| panic!("Failed to decode balanceOf return: {e}"))
}

pub async fn send_approve_tx(
    rpc_url: String, private_key: String,
    max_fee: u128, max_priority_fee: u128, gas_limit: u64,
    token: Address, spender: Address, amount: U256,
) -> Result<(), String> {
    let calldata = IERC20::approveCall { spender, amount }.abi_encode();
    send_simple_tx(rpc_url, private_key, max_fee, max_priority_fee, gas_limit, token, calldata.into(), "approve").await
}

pub async fn send_deposit_tx(
    rpc_url: String, private_key: String,
    max_fee: u128, max_priority_fee: u128, gas_limit: u64,
    privacy_pool: Address, secret_nullifier_hash: U256, amount: U256, token: Address,
) -> Result<(), String> {
    let calldata = IPrivacyPoolCommon::depositCall {
        secretNullifierHash: secret_nullifier_hash,
        amount,
        token,
    }.abi_encode();
    send_simple_tx(rpc_url, private_key, max_fee, max_priority_fee, gas_limit, privacy_pool, calldata.into(), "deposit").await
}

pub async fn try_call_next_leaf_index(rpc_url: String, privacy_pool: Address) -> Option<u64> {
    let data = IPrivacyPoolCommon::getNextLeafIndexCall {}.abi_encode();
    let raw = match run_eth_call(rpc_url, privacy_pool, data.into()).await {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(err = %e, "getNextLeafIndex eth_call failed");
            return None;
        }
    };
    match IPrivacyPoolCommon::getNextLeafIndexCall::abi_decode_returns(&raw) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!(err = %e, raw = %hex::encode(raw.as_ref()), "Failed to decode getNextLeafIndex return");
            None
        }
    }
}

pub async fn try_call_current_root(rpc_url: String, privacy_pool: Address) -> Option<U256> {
    let data = IPrivacyPoolCommon::getCurrentRootCall {}.abi_encode();
    let raw = match run_eth_call(rpc_url, privacy_pool, data.into()).await {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(err = %e, "getCurrentRoot eth_call failed");
            return None;
        }
    };
    match IPrivacyPoolCommon::getCurrentRootCall::abi_decode_returns(&raw) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!(err = %e, raw = %hex::encode(raw.as_ref()), "Failed to decode getCurrentRoot return");
            None
        }
    }
}

pub async fn build_offchain_merkle_tree(rpc_url: String, privacy_pool: Address) -> OffchainMerkleTree {
    let logs = Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url.parse().map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );
        let filter = Filter::new()
            .address(privacy_pool)
            .from_block(0u64)
            .event("Deposit(uint256,uint256,address,uint64,uint256)");
        provider
            .get_logs(&filter)
            .await
            .map_err(|e| format!("Failed to fetch Deposit logs: {e}"))
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

#[allow(dead_code)]
pub async fn ensure_owner_has_eth_for_gas(
    rpc_url: String,
    owner_private_key: String,
    target_balance_hex: &str,
) {
    let target_balance_hex = target_balance_hex.to_string();

    Compat::new(async move {
        let signer: PrivateKeySigner = owner_private_key
            .parse()
            .unwrap_or_else(|e| panic!("Invalid private key: {e}"));
        let owner = signer.address();
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .unwrap_or_else(|e| panic!("Invalid RPC URL: {e}")),
        );
        let target_balance =
            U256::from_str_radix(target_balance_hex.trim_start_matches("0x"), 16)
                .unwrap_or_else(|e| panic!("Invalid ANVIL_TOPUP_BALANCE_HEX: {e}"));

        match provider.anvil_set_balance(owner, target_balance).await {
            Ok(()) => tracing::info!(owner = %owner, "Topped up owner ETH balance on Anvil"),
            Err(e) => tracing::warn!(
                owner = %owner,
                err = %e,
                "Failed to top up owner ETH balance (continuing)"
            ),
        }
    })
    .await;
}