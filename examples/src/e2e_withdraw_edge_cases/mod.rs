use alloy::primitives::U256;
use clap::Parser;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    WithdrawInputs, build_onchain_verification_input, compute_commitment_hash,
    offchain_merkle::OffchainMerkleTree,
    poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
    prove_withdraw, send_withdraw_with_proof_tx, verify_withdraw,
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use crate::e2e_withdraw::{AppState, chain};

fn mock_tlsn(amount: u32) -> (Vec<u8>, [u8; 16], [u8; 32]) {
    let fragment = format!("{:012}", amount).into_bytes();
    let blinder = [7u8; 16];
    let commitment_hash = compute_commitment_hash(&fragment, &blinder);
    (fragment, blinder, commitment_hash)
}

struct DepositResult {
    merkle_index: u32,
    secret: BaseField,
    nullifier: BaseField,
    merkle_siblings: Vec<BaseField>,
    merkle_root: BaseField,
    commitment_amount: BaseField,
}

async fn do_deposit(app: &AppState, secret_base: u32, nullifier_base: u32, amount: u32) -> DepositResult {
    chain::ensure_owner_has_eth_for_gas(app).await;

    let token_address = BaseField::from_u32_unchecked(chain::address_to_m31(app.withdraw_token));
    let commitment_amount = BaseField::from_u32_unchecked(amount);

    let mut offchain_tree: OffchainMerkleTree = chain::build_offchain_merkle_tree(app).await;
    let merkle_index = u32::try_from(offchain_tree.leaf_count())
        .expect("leaf_count fits u32");

    let secret = BaseField::from_u32_unchecked(secret_base.wrapping_add(merkle_index));
    let nullifier = BaseField::from_u32_unchecked(nullifier_base.wrapping_add(merkle_index));

    let deposit_inputs = ChainInputs::for_deposit(secret, nullifier, commitment_amount, token_address);
    let (_, deposit_outputs) = gen_poseidon_chain_trace(4, deposit_inputs);
    let offchain_index = offchain_tree.add_leaf(deposit_outputs.leaf);
    let (merkle_siblings, _) = offchain_tree.path(offchain_index as usize);
    let merkle_root = offchain_tree.root();

    let amount_u64 = amount as u64;

    chain::send_approve_tx(app, U256::from(amount_u64))
        .await
        .expect("approve failed");
    chain::send_deposit_tx(app, U256::from(deposit_outputs.secret_nullifier_hash.0), U256::from(amount_u64))
        .await
        .expect("deposit failed");

    DepositResult {
        merkle_index,
        secret,
        nullifier,
        merkle_siblings,
        merkle_root,
        commitment_amount,
    }
}

async fn build_and_submit_withdraw(
    app: &AppState,
    deposit: &DepositResult,
    withdraw_amount: u32,
    // Overrides the `root` parameter sent to the contract (not used in proof generation).
    // Use this to test InvalidRoot rejection without breaking proof generation.
    override_contract_root: Option<BaseField>,
) -> Result<String, String> {
    let (balance_fragment, blinder, commitment_hash) = mock_tlsn(withdraw_amount);
    let token_address = BaseField::from_u32_unchecked(chain::address_to_m31(app.withdraw_token));

    let commitment_amount = deposit.commitment_amount;
    let withdraw_amount_field = BaseField::from_u32_unchecked(withdraw_amount);
    let refund_amount = BaseField::from_u32_unchecked(
        commitment_amount.0.wrapping_sub(withdraw_amount),
    );

    let inputs = WithdrawInputs {
        balance_fragment,
        blinder,
        commitment_hash,
        secret: deposit.secret,
        nullifier: deposit.nullifier,
        commitment_amount,
        withdraw_amount: withdraw_amount_field,
        refund_secret: BaseField::from_u32_unchecked(deposit.secret.0.wrapping_add(1_000_000)),
        refund_nullifier: BaseField::from_u32_unchecked(deposit.nullifier.0.wrapping_add(1_000_000)),
        refund_amount,
        token_address,
        merkle_siblings: deposit.merkle_siblings.clone(),
        merkle_index: deposit.merkle_index,
        merkle_root: deposit.merkle_root,
    };

    let proof = prove_withdraw(inputs, 8).expect("proof generation failed");
    verify_withdraw(proof.clone()).expect("off-chain verification failed");

    let verify_input =
        build_onchain_verification_input(&proof).expect("failed to build onchain input");

    let contract_root = override_contract_root
        .map(|r| U256::from(r.0))
        .unwrap_or(U256::from(proof.public_inputs.merkle_root.0));

    send_withdraw_with_proof_tx(
        &app.rpc_url,
        &app.owner_private_key,
        app.privacy_pool_address,
        app.withdraw_gas_limit,
        contract_root,
        U256::from(proof.public_inputs.nullifier.0),
        app.withdraw_token,
        U256::from(proof.public_inputs.amount.0),
        app.withdraw_recipient,
        U256::from(proof.public_inputs.refund_commitment_hash.0),
        &verify_input,
    )
    .await
}

async fn test_double_spend(app: &AppState) {
    tracing::info!("--- TEST: double spend (same nullifier) ---");
    let deposit = do_deposit(app, app.withdraw_secret, app.withdraw_nullifier, app.deposit_amount).await;

    let tx = build_and_submit_withdraw(app, &deposit, app.deposit_amount / 2, None)
        .await
        .expect("first withdraw should succeed");
    tracing::info!(%tx, "First withdraw: OK");

    let result = build_and_submit_withdraw(app, &deposit, app.deposit_amount / 2, None).await;
    match result {
        Err(e) if e.contains("NullifierAlreadyUsed") || e.contains("reverted") => {
            tracing::info!("Second withdraw correctly rejected: {e}");
            tracing::info!("✅ PASS: double spend rejected");
        }
        Err(e) => panic!("Unexpected error on double spend: {e}"),
        Ok(tx) => panic!("FAIL: double spend should have been rejected, but got tx {tx}"),
    }
}

async fn test_invalid_root(app: &AppState) {
    tracing::info!("--- TEST: invalid merkle root ---");
    let deposit = do_deposit(app, app.withdraw_secret.wrapping_add(100), app.withdraw_nullifier.wrapping_add(100), app.deposit_amount).await;

    // Use a root that was never committed on-chain
    let fake_root = BaseField::from_u32_unchecked(12345);
    let result = build_and_submit_withdraw(app, &deposit, app.deposit_amount / 2, Some(fake_root)).await;
    match result {
        Err(e) if e.contains("InvalidRoot") || e.contains("reverted") => {
            tracing::info!("Withdraw with fake root correctly rejected: {e}");
            tracing::info!("✅ PASS: invalid root rejected");
        }
        Err(e) => panic!("Unexpected error on invalid root test: {e}"),
        Ok(tx) => panic!("FAIL: invalid root should have been rejected, but got tx {tx}"),
    }
}

async fn test_full_withdrawal(app: &AppState) {
    tracing::info!("--- TEST: full withdrawal (withdraw_amount == deposit_amount) ---");
    let deposit = do_deposit(app, app.withdraw_secret.wrapping_add(200), app.withdraw_nullifier.wrapping_add(200), app.deposit_amount).await;

    let tx = build_and_submit_withdraw(app, &deposit, app.deposit_amount, None)
        .await
        .expect("full withdrawal should succeed");
    tracing::info!(%tx, "✅ PASS: full withdrawal accepted");
}

pub fn run() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_span_events(FmtSpan::NONE)
        .init();

    smol::block_on(async {
        let app = AppState::parse();

        test_double_spend(&app).await;
        test_invalid_root(&app).await;
        test_full_withdrawal(&app).await;

        tracing::info!("✅ All edge case tests passed");
    });
}
