use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use async_compat::Compat;

use super::types::{IPrivacyPool, IStwoVerifier, OnchainVerificationInput};

pub async fn verify_onchain_call(
    rpc_url: &str,
    verifier_address: Address,
    input: OnchainVerificationInput,
) -> Result<bool, String> {
    let rpc_url = rpc_url.to_string();
    Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let call_data = IStwoVerifier::verifyCall {
            proof: input.proof,
            params: input.params,
            treeRoots: input.tree_roots,
            treeColumnLogSizes: input.tree_column_log_sizes,
            digest: input.digest,
            nDraws: input.n_draws,
        };

        let tx = TransactionRequest::default()
            .to(verifier_address)
            .input(call_data.abi_encode().into());

        let raw = provider
            .call(tx)
            .await
            .map_err(|err| format!("Verifier contract call reverted: {err}"))?;

        let decoded = IStwoVerifier::verifyCall::abi_decode_returns(&raw)
            .map_err(|e| format!("Failed to decode verify() return value: {e}"))?;

        Ok(decoded)
    })
    .await
}

pub fn build_verify_calldata(input: &OnchainVerificationInput) -> Bytes {
    IStwoVerifier::verifyCall {
        proof: input.proof.clone(),
        params: input.params.clone(),
        treeRoots: input.tree_roots.clone(),
        treeColumnLogSizes: input.tree_column_log_sizes.clone(),
        digest: input.digest,
        nDraws: input.n_draws,
    }
    .abi_encode()
    .into()
}

// TODO delete later
pub async fn simulate_withdraw_with_proof_call(
    rpc_url: &str,
    pool_address: Address,
    root: U256,
    nullifier: U256,
    token: Address,
    amount: U256,
    recipient: Address,
    refund_commitment_hash: U256,
    verify_input: &OnchainVerificationInput,
) -> Result<(), String> {
    let verify_calldata = build_verify_calldata(verify_input);
    let rpc_url = rpc_url.to_string();
    Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let call_data = IPrivacyPool::withdrawCall {
            root,
            nullifier,
            token,
            amount,
            recipient,
            refundCommitmentHash: refund_commitment_hash,
            verifyCalldata: verify_calldata,
        };

        let tx = TransactionRequest::default()
            .to(pool_address)
            .input(call_data.abi_encode().into());

        provider
            .call(tx)
            .await
            .map_err(|err| format!("PrivacyPool withdraw simulation reverted: {err}"))?;

        Ok(())
    })
    .await
}

pub async fn send_withdraw_with_proof_tx(
    rpc_url: &str,
    sender_private_key: &str,
    pool_address: Address,
    root: U256,
    nullifier: U256,
    token: Address,
    amount: U256,
    recipient: Address,
    refund_commitment_hash: U256,
    verify_input: &OnchainVerificationInput,
) -> Result<String, String> {
    let verify_calldata = build_verify_calldata(verify_input);
    let rpc_url = rpc_url.to_string();
    let sender_private_key = sender_private_key.to_string();
    Compat::new(async move {
        let signer: PrivateKeySigner = sender_private_key
            .parse()
            .map_err(|e| format!("Invalid sender private key: {e}"))?;
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new().wallet(wallet).connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );

        let call_data = IPrivacyPool::withdrawCall {
            root,
            nullifier,
            token,
            amount,
            recipient,
            refundCommitmentHash: refund_commitment_hash,
            verifyCalldata: verify_calldata,
        };

        let tx = TransactionRequest::default()
            .to(pool_address)
            .input(call_data.abi_encode().into());

        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|err| format!("withdraw send_transaction failed: {err}"))?;

        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|err| format!("withdraw receipt failed for tx {tx_hash}: {err}"))?;

        if !receipt.status() {
            return Err(format!(
                "withdraw transaction reverted, tx hash: {}, gas_used: {}",
                receipt.transaction_hash, receipt.gas_used
            ));
        }

        Ok(receipt.transaction_hash.to_string())
    })
    .await
}
