use alloy::primitives::{Bytes, U256};
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    OfferSpendInputs, build_offer_onchain_verification_input, build_verify_calldata,
    prove_offer_withdraw, verify_offer_withdraw,
    poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use self::{
    chain::{
        build_offchain_merkle_tree, send_approve_tx, send_cancel_offer_tx, send_create_offer_tx,
        send_deposit_tx, try_call_current_root, try_call_next_leaf_index,
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

        let deposit_amount = BaseField::from_u32_unchecked(app.deposit_amount);
        let token_address = BaseField::from_u32_unchecked(chain::address_to_m31(app.token_address));

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

        let effective_secret_u32 = app.deposit_secret.wrapping_add(idx_before as u32);
        let effective_nullifier_u32 = app.deposit_nullifier.wrapping_add(idx_before as u32);
        let deposit_secret = BaseField::from_u32_unchecked(effective_secret_u32);
        let deposit_nullifier = BaseField::from_u32_unchecked(effective_nullifier_u32);

        tracing::info!(
            deposit_amount = app.deposit_amount,
            merkle_index = idx_before,
            effective_secret = effective_secret_u32,
            effective_nullifier = effective_nullifier_u32,
            "Creating 2 offers: Offer1=30, Offer2=40 from deposit of 100"
        );

        let deposit_inputs = ChainInputs::for_deposit(
            deposit_secret,
            deposit_nullifier,
            deposit_amount,
            token_address,
        );
        let (_, deposit_outputs) = gen_poseidon_chain_trace(4, deposit_inputs);
        let secret_nullifier_hash = deposit_outputs.secret_nullifier_hash;
        let deposit_leaf = deposit_outputs.leaf;

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
        let (merkle_siblings, _) = offchain_tree.path(merkle_index as usize);
        let merkle_root = offchain_tree.root();

        assert_eq!(
            U256::from(merkle_root.0),
            root_after,
            "Merkle root mismatch (off-chain vs on-chain)"
        );

        let withdraw_amount = BaseField::from_u32_unchecked(30);
        let refund_amount = BaseField::from_u32_unchecked(70);

        let refund_offset = 1_000_000u32;
        let refund_secret = BaseField::from_u32_unchecked(
            effective_secret_u32.wrapping_add(refund_offset),
        );
        let refund_nullifier = BaseField::from_u32_unchecked(
            effective_nullifier_u32.wrapping_add(refund_offset),
        );

        let inputs = OfferSpendInputs {
            secret: deposit_secret,
            nullifier: deposit_nullifier,
            commitment_amount: deposit_amount,
            withdraw_amount,
            refund_secret,
            refund_nullifier,
            refund_amount,
            token_address,
            merkle_siblings,
            merkle_index,
            merkle_root,
        };

        tracing::info!("Generating offer-withdraw proof");
        let proof = prove_offer_withdraw(inputs, 8).expect("Offer proof generation failed");
        verify_offer_withdraw(proof.clone()).expect("Offer proof verification failed");

        tracing::info!("Building on-chain verification payload");
        let verify_input =
            build_offer_onchain_verification_input(&proof).expect("Failed to build onchain input");
        let verify_calldata = build_verify_calldata(&verify_input);

        tracing::info!("Calling createOffer transaction");
        let secret_hash = U256::from(12345u64.wrapping_add(idx_before));
        let currency = "USD".to_string();
        let fiat_amount = U256::from(0);
        let rev_tag = "@alice".to_string();

        send_create_offer_tx(
            &app,
            U256::from(proof.merkle_root.0),
            U256::from(proof.nullifier.0),
            app.token_address,
            U256::from(proof.amount.0),
            U256::from(proof.refund_commitment_hash.0),
            secret_hash,
            currency,
            fiat_amount,
            rev_tag,
            Bytes::from(verify_calldata),
        )
        .await
        .expect("Failed to send createOffer transaction");

        tracing::info!("✅ Offer 1 created successfully");

        // Create second offer from first offer's refund commitment
        tracing::info!("Creating second offer from refund commitment");
        
        let _idx_after_offer1 = try_call_next_leaf_index(&app)
            .await
            .unwrap_or_else(|| panic!("getNextLeafIndex unavailable after offer1"));
        let root_after_offer1 = try_call_current_root(&app)
            .await
            .unwrap_or_else(|| panic!("getCurrentRoot unavailable after offer1"));

        offchain_tree.add_leaf(proof.refund_commitment_hash);
        assert_eq!(
            U256::from(offchain_tree.root().0),
            root_after_offer1,
            "Merkle root mismatch after offer1"
        );

        let offer2_merkle_index = u32::try_from(idx_after)
            .unwrap_or_else(|_| panic!("Offer2 leaf index does not fit u32: {idx_after}"));
        let (offer2_merkle_siblings, _) = offchain_tree.path(offer2_merkle_index as usize);
        let offer2_merkle_root = offchain_tree.root();

        let offer2_withdraw_amount = BaseField::from_u32_unchecked(40);
        let offer2_refund_amount = BaseField::from_u32_unchecked(30);
        let offer2_amount = 40u32; // Store for cancelOffer later
        let offer2_offset = 3_000_000u32;
        let offer2_refund_secret = BaseField::from_u32_unchecked(
            effective_secret_u32.wrapping_add(offer2_offset),
        );
        let offer2_refund_nullifier = BaseField::from_u32_unchecked(
            effective_nullifier_u32.wrapping_add(offer2_offset),
        );

        let offer2_inputs = OfferSpendInputs {
            secret: refund_secret,
            nullifier: refund_nullifier,
            commitment_amount: refund_amount,
            withdraw_amount: offer2_withdraw_amount,
            refund_secret: offer2_refund_secret,
            refund_nullifier: offer2_refund_nullifier,
            refund_amount: offer2_refund_amount,
            token_address,
            merkle_siblings: offer2_merkle_siblings,
            merkle_index: offer2_merkle_index,
            merkle_root: offer2_merkle_root,
        };

        tracing::info!("Generating second offer proof");
        let offer2_proof = prove_offer_withdraw(offer2_inputs, 8).expect("Offer2 proof generation failed");
        verify_offer_withdraw(offer2_proof.clone()).expect("Offer2 proof verification failed");

        tracing::info!("Building second offer on-chain verification payload");
        let offer2_verify_input =
            build_offer_onchain_verification_input(&offer2_proof).expect("Failed to build offer2 onchain input");
        let offer2_verify_calldata = build_verify_calldata(&offer2_verify_input);

        tracing::info!("Calling createOffer transaction for offer2");
        let secret_hash_2 = U256::from(12345u64.wrapping_add(idx_before).wrapping_add(1));
        let currency_2 = "EUR".to_string();
        let fiat_amount_2 = U256::from(0);
        let rev_tag_2 = "@bob".to_string();

        send_create_offer_tx(
            &app,
            U256::from(offer2_proof.merkle_root.0),
            U256::from(offer2_proof.nullifier.0),
            app.token_address,
            U256::from(offer2_proof.amount.0),
            U256::from(offer2_proof.refund_commitment_hash.0),
            secret_hash_2,
            currency_2,
            fiat_amount_2,
            rev_tag_2,
            Bytes::from(offer2_verify_calldata),
        )
        .await
        .expect("Failed to send createOffer transaction for offer2");

        tracing::info!("✅ Offer 2 created successfully");

        tracing::info!("Cancelling second offer");
        
        let root_after_offer2 = try_call_current_root(&app)
            .await
            .unwrap_or_else(|| panic!("getCurrentRoot unavailable after offer2"));

        offchain_tree.add_leaf(offer2_proof.refund_commitment_hash);
        
        assert_eq!(
            U256::from(offchain_tree.root().0),
            root_after_offer2,
            "Merkle root mismatch after offer2"
        );

        // Cancel uses offer2's refund commitment (which is at _idx_after_offer1 position)
        let cancel_merkle_index = u32::try_from(_idx_after_offer1)
            .unwrap_or_else(|_| panic!("Cancel leaf index does not fit u32: {_idx_after_offer1}"));
        let (cancel_merkle_siblings, _) = offchain_tree.path(cancel_merkle_index as usize);
        let cancel_merkle_root = offchain_tree.root();

        let cancel_refund_amount = offer2_refund_amount; // 30 tokens from offer2's refund
        let cancel_offset = 4_000_000u32;
        let cancel_secret = BaseField::from_u32_unchecked(
            effective_secret_u32.wrapping_add(cancel_offset),
        );
        let cancel_nullifier = BaseField::from_u32_unchecked(
            effective_nullifier_u32.wrapping_add(cancel_offset),
        );

        let cancel_inputs = OfferSpendInputs {
            secret: offer2_refund_secret,
            nullifier: offer2_refund_nullifier,
            commitment_amount: cancel_refund_amount,
            withdraw_amount: cancel_refund_amount,
            refund_secret: cancel_secret,
            refund_nullifier: cancel_nullifier,
            refund_amount: BaseField::from_u32_unchecked(0),
            token_address,
            merkle_siblings: cancel_merkle_siblings,
            merkle_index: cancel_merkle_index,
            merkle_root: cancel_merkle_root,
        };

        tracing::info!("Generating cancel proof");
        let cancel_proof = prove_offer_withdraw(cancel_inputs, 8).expect("Cancel proof generation failed");
        verify_offer_withdraw(cancel_proof.clone()).expect("Cancel proof verification failed");

        tracing::info!("Building cancel verification payload");
        let cancel_verify_input = build_offer_onchain_verification_input(&cancel_proof)
            .expect("Failed to build cancel onchain input");
        let cancel_verify_calldata = build_verify_calldata(&cancel_verify_input);
        let cancel_hash = U256::from(54321u64);

        tracing::info!("Calling cancelOffer transaction");
        send_cancel_offer_tx(
            &app,
            U256::from(cancel_proof.merkle_root.0),
            U256::from(cancel_proof.nullifier.0),
            app.token_address,
            U256::from(offer2_amount), // Original offer2 amount (40), not refund amount
            U256::from(cancel_proof.refund_commitment_hash.0),
            secret_hash_2,
            cancel_hash,
            Bytes::from(cancel_verify_calldata),
        )
        .await
        .expect("Failed to send cancelOffer transaction");

        tracing::info!(
            "✅ Two offers created (30 + 40 tokens) and second offer cancelled with proof verification"
        );
          
        
    });
}