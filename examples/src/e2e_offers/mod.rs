use alloy::primitives::U256;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    OfferSpendInputs, prove_offer_withdraw, verify_offer_withdraw,
    poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use self::{
    chain::{
        build_offchain_merkle_tree, send_approve_tx, send_deposit_tx, try_call_current_root,
        try_call_next_leaf_index,
    },
    config::AppState,
};

mod chain;
mod config;

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
        let app = AppState::from_env();

        if app.offer_amount > app.deposit_amount {
            panic!(
                "Invalid config: offer_amount ({}) > deposit_amount ({})",
                app.offer_amount, app.deposit_amount
            );
        }

        let deposit_amount = BaseField::from_u32_unchecked(app.deposit_amount);
        tracing::info!(
            deposit_amount = app.deposit_amount,
            offer_amount = app.offer_amount,
            "Amounts"
        );
        let token_address = BaseField::from_u32_unchecked(chain::address_to_m31(app.token_address));

        let deposit_secret = BaseField::from_u32_unchecked(app.deposit_secret);
        let deposit_nullifier = BaseField::from_u32_unchecked(app.deposit_nullifier);

        let deposit_inputs = ChainInputs::for_deposit(
            deposit_secret,
            deposit_nullifier,
            deposit_amount,
            token_address,
        );
        let (_, deposit_outputs) = gen_poseidon_chain_trace(4, deposit_inputs);
        let secret_nullifier_hash = deposit_outputs.secret_nullifier_hash;
        let deposit_leaf = deposit_outputs.leaf;

        let idx_before = try_call_next_leaf_index(&app)
            .await
            .unwrap_or_else(|| panic!("getNextLeafIndex unavailable"));
        let root_before = try_call_current_root(&app)
            .await
            .unwrap_or_else(|| panic!("getCurrentRoot unavailable"));

        let mut offchain_tree = build_offchain_merkle_tree(&app)
            .await
            .unwrap_or_else(|e| panic!("Failed to build off-chain Merkle tree: {e}"));
        assert_eq!(
            offchain_tree.leaf_count(),
            idx_before,
            "Off-chain leaf count mismatch before deposit"
        );

        send_approve_tx(&app, U256::from(deposit_amount.0))
            .await
            .expect("approve failed");

        send_deposit_tx(
            &app,
            U256::from(secret_nullifier_hash.0),
            U256::from(deposit_amount.0),
        )
        .await
        .unwrap();

        let idx_after = try_call_next_leaf_index(&app)
            .await
            .unwrap_or_else(|| panic!("getNextLeafIndex unavailable after deposit"));
        let root_after = try_call_current_root(&app)
            .await
            .unwrap_or_else(|| panic!("getCurrentRoot unavailable after deposit"));

        assert_eq!(idx_after, idx_before + 1, "Leaf index did not increment");
        assert_ne!(root_after, root_before, "Merkle root did not change");

        offchain_tree.add_leaf(deposit_leaf);
        let offchain_root_u256 = U256::from(offchain_tree.root().0);
        assert_eq!(
            offchain_root_u256, root_after,
            "On-chain root mismatch vs off-chain reconstructed root"
        );

        let merkle_index = u32::try_from(idx_before)
            .unwrap_or_else(|_| panic!("Leaf index does not fit u32: {idx_before}"));
        let (merkle_siblings, _path_bits) = offchain_tree.path(merkle_index as usize);
        let merkle_root = offchain_tree.root();

        assert_eq!(
            U256::from(merkle_root.0),
            root_after,
            "Merkle root mismatch (off-chain vs on-chain)"
        );

        tracing::info!(
            merkle_index,
            merkle_depth = merkle_siblings.len(),
            merkle_root = merkle_root.0,
            "Prepared Merkle proof inputs"
        );

        let withdraw_amount = BaseField::from_u32_unchecked(app.offer_amount);
        let refund_amount =
            BaseField::from_u32_unchecked(app.deposit_amount.wrapping_sub(app.offer_amount));

        let inputs = OfferSpendInputs {
            secret: deposit_secret,
            nullifier: deposit_nullifier,
            commitment_amount: deposit_amount,
            withdraw_amount,
            refund_secret: BaseField::from_u32_unchecked(app.deposit_secret.wrapping_add(1_000_000)),
            refund_nullifier: BaseField::from_u32_unchecked(
                app.deposit_nullifier.wrapping_add(1_000_000),
            ),
            refund_amount,
            token_address,
            merkle_siblings,
            merkle_index,
            merkle_root,
        };

        tracing::info!("Generating offer-withdraw proof");
        let proof = prove_offer_withdraw(inputs, 8).expect("Offer proof generation failed");
        verify_offer_withdraw(proof).expect("Offer proof verification failed");

        tracing::info!(
            idx_before,
            idx_after,
            root_before = %root_before,
            root_after = %root_after,
            "Offer flow completed with proof generation"
        );
          
    });
}
