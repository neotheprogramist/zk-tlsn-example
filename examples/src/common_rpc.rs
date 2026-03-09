use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder, ext::AnvilApi},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use async_compat::Compat;

pub const M31_MODULUS: u32 = 2_147_483_647;

pub fn address_to_m31(address: Address) -> u32 {
    let address_u256 = U256::from_be_slice(address.as_slice());
    let reduced = address_u256 % U256::from(M31_MODULUS);
    u32::try_from(reduced).expect("Address modulo M31 should fit into u32")
}

pub async fn send_simple_tx(
    rpc_url: String,
    owner_private_key: String,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
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
            .max_priority_fee_per_gas(max_priority_fee_per_gas);

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
