use alloy::primitives::{Bytes, U256};
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    OfferSpendInputs, build_offer_onchain_verification_input, build_verify_calldata,
    prove_offer_withdraw, verify_offer_withdraw,
    poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
    offchain_merkle::poseidon_hash_pair,
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use self::{
    chain::{
        build_offchain_merkle_tree, send_approve_tx, send_cancel_claim_tx, send_cancel_intent_tx,
        send_create_offer_tx, send_deposit_tx, try_call_current_root, try_call_next_leaf_index,
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

        let mut offchain_tree = build_offchain_merkle_tree(&app)
            .await
            .unwrap_or_else(|e| panic!("Failed to build off-chain Merkle tree: {e}"));
        
        let idx_before = offchain_tree.leaf_count() as u64;

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

        // Verify deposit succeeded by checking index incremented and root matches our tree
        let idx_after = try_call_next_leaf_index(&app)
            .await
            .unwrap_or_else(|| panic!("getNextLeafIndex unavailable after deposit"));
        let root_after = try_call_current_root(&app)
            .await
            .unwrap_or_else(|| panic!("getCurrentRoot unavailable after deposit"));

        assert_eq!(idx_after, idx_before + 1, "Leaf index did not increment");

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
        
        // ========== OFFER 1: Create offer for 30 tokens from deposit of 100 ==========
        let offer1_amount = BaseField::from_u32_unchecked(30);
        let offer1_refund_amount = BaseField::from_u32_unchecked(70);

        // Secrets for offer1 refund commitment (70 tokens)
        let offer1_refund_secret = BaseField::from_u32_unchecked(2006);
        let offer1_refund_nullifier = BaseField::from_u32_unchecked(2008);

        let offer1_inputs = OfferSpendInputs {
            secret: deposit_secret,
            nullifier: deposit_nullifier,
            commitment_amount: deposit_amount,
            offer_amount: offer1_amount,
            refund_secret: offer1_refund_secret,
            refund_nullifier: offer1_refund_nullifier,
            refund_amount: offer1_refund_amount,
            token_address,
            merkle_siblings,
            merkle_index,
            merkle_root,
        };

        tracing::info!("Generating offer-withdraw proof");
        let offer1_proof = prove_offer_withdraw(offer1_inputs, 8).expect("Offer proof generation failed");
        verify_offer_withdraw(offer1_proof.clone()).expect("Offer proof verification failed");

        tracing::info!("Building on-chain verification payload");
        let offer1_verify_input =
            build_offer_onchain_verification_input(&offer1_proof).expect("Failed to build onchain input");
        let offer1_verify_calldata = build_verify_calldata(&offer1_verify_input);

        tracing::info!("Calling createOffer transaction");
        let secret_hash = U256::from(12345u64.wrapping_add(idx_before));
        let currency = "USD".to_string();
        let fiat_amount = U256::from(0);
        let rev_tag = "@alice".to_string();

        send_create_offer_tx(
            &app,
            U256::from(offer1_proof.merkle_root.0),
            U256::from(offer1_proof.nullifier.0),
            app.token_address,
            U256::from(offer1_proof.amount.0),
            U256::from(offer1_proof.refund_commitment_hash.0),
            secret_hash,
            currency,
            fiat_amount,
            rev_tag,
            Bytes::from(offer1_verify_calldata),
        )
        .await
        .expect("Failed to send createOffer transaction");

        tracing::info!("✅ Offer 1 created successfully");

        // Create second offer from first offer's refund commitment
        tracing::info!("Creating second offer from refund commitment");
        
        tracing::info!(
            refund_commitment = offer1_proof.refund_commitment_hash.0,
            "Adding offer1 refund commitment to offchain tree"
        );
        offchain_tree.add_leaf(offer1_proof.refund_commitment_hash);
        
        let onchain_root_after_offer1 = try_call_current_root(&app)
            .await
            .unwrap_or_else(|| panic!("getCurrentRoot unavailable after offer1"));
        let offchain_root_after_offer1 = U256::from(offchain_tree.root().0);
        
        tracing::info!(
            onchain_root = %onchain_root_after_offer1,
            offchain_root = %offchain_root_after_offer1,
            "Merkle roots after offer1"
        );
        
        assert_eq!(
            onchain_root_after_offer1, offchain_root_after_offer1,
            "Merkle root mismatch after offer1"
        );
        let idx_after_offer1 = (offchain_tree.leaf_count() - 1) as u64;  // Local calculation - no RPC!

        let offer2_merkle_index = u32::try_from(idx_after_offer1)
            .unwrap_or_else(|_| panic!("Offer2 leaf index does not fit u32: {idx_after_offer1}"));
        let (offer2_merkle_siblings, _) = offchain_tree.path(offer2_merkle_index as usize);
        let offer2_merkle_root = offchain_tree.root();

        let offer2_amount_bf = BaseField::from_u32_unchecked(40);
        let offer2_refund_amount = BaseField::from_u32_unchecked(30);
        
        // Secrets for offer2 refund commitment (30 tokens)
        let offer2_refund_secret = BaseField::from_u32_unchecked(3004);
        let offer2_refund_nullifier = BaseField::from_u32_unchecked(3002);

        let offer2_inputs = OfferSpendInputs {
            secret: offer1_refund_secret,
            nullifier: offer1_refund_nullifier,
            commitment_amount: offer1_refund_amount,
            offer_amount: offer2_amount_bf,
            refund_secret: offer2_refund_secret,
            refund_nullifier: offer2_refund_nullifier,
            refund_amount: offer2_refund_amount,
            token_address,
            merkle_siblings: offer2_merkle_siblings,
            merkle_index: offer2_merkle_index,
            merkle_root: offer2_merkle_root,
        };

        tracing::info!(
            offer2_secret = offer1_refund_secret.0,
            offer2_nullifier = offer1_refund_nullifier.0,
            offer2_amount = offer1_refund_amount.0,
            merkle_index = offer2_merkle_index,
            "Generating second offer proof"
        );
        let offer2_proof = prove_offer_withdraw(offer2_inputs, 8).expect("Offer2 proof generation failed");
        verify_offer_withdraw(offer2_proof.clone()).expect("Offer2 proof verification failed");
        
        tracing::info!(
            merkle_root = offer2_proof.merkle_root.0,
            nullifier = offer2_proof.nullifier.0,
            amount = offer2_proof.amount.0,
            refund_commitment = offer2_proof.refund_commitment_hash.0,
            "Offer2 proof generated"
        );

        tracing::info!("Building second offer on-chain verification payload");
        let offer2_verify_input =
            build_offer_onchain_verification_input(&offer2_proof).expect("Failed to build offer2 onchain input");
        let offer2_verify_calldata = build_verify_calldata(&offer2_verify_input);

        tracing::info!("Calling createOffer transaction for offer2");
        // Create offerSecret and hash it: offerSecretHash = poseidon(offerSecret, offerSecret)
        let offer2_secret = BaseField::from_u32_unchecked(77777);
        let offer2_secret_hash = poseidon_hash_pair(offer2_secret, offer2_secret);
        let secret_hash_2 = U256::from(offer2_secret_hash.0);
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
        
        // Step 1: Cancel Intent - reveal offerSecret to prove ownership
        let cancel_secret = BaseField::from_u32_unchecked(99999);
        let cancel_hash_bf = poseidon_hash_pair(cancel_secret, cancel_secret);
        let cancel_hash = U256::from(cancel_hash_bf.0);

        tracing::info!("Calling cancelIntent transaction");
        send_cancel_intent_tx(
            &app,
            U256::from(offer2_secret.0), // Reveal offerSecret
            cancel_hash,
        )
        .await
        .expect("Failed to send cancelIntent transaction");

        tracing::info!("✅ Offer cancelled (intent registered)");

        // Step 2: Cancel Claim - create commitment for offer amount (40 tokens)
        let cancel_claim_secret = BaseField::from_u32_unchecked(4004);
        let cancel_claim_nullifier = BaseField::from_u32_unchecked(4005);

        let cancel_claim_inputs = ChainInputs::for_deposit(
            cancel_claim_secret,
            cancel_claim_nullifier,
            offer2_amount_bf, // 40 tokens - offer amount
            token_address,
        );
        let (_, cancel_claim_outputs) = gen_poseidon_chain_trace(4, cancel_claim_inputs);

        tracing::info!("Calling cancelClaim transaction");
        send_cancel_claim_tx(
            &app,
            secret_hash_2, // offerHash
            U256::from(cancel_secret.0), // Reveal cancelSecret
            U256::from(cancel_claim_outputs.secret_nullifier_hash.0),
        )
        .await
        .expect("Failed to send cancelClaim transaction");

        tracing::info!(
            "✅ Two offers created (30 + 40 tokens) and second offer cancelled (refund 30 stays + new commitment 40 created)"
        );
          
        
    });
}