use alloy::primitives::U256;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    OfferCreateInputs, build_offer_onchain_verification_input,
    prove_offer_create, verify_offer_create,
    poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
    offchain_merkle::poseidon_hash_pair,
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use crate::common_rpc;

use self::{
    chain::{
        send_cancel_claim_tx, send_cancel_intent_tx, send_create_offer_tx,
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
        let token_address = common_rpc::address_to_m31(app.token_address);

        let mut offchain_tree = crate::common_rpc::build_offchain_merkle_tree(
            app.rpc_url.clone(),
            app.privacy_pool_address,
        ).await;
        
        let idx_before = offchain_tree.leaf_count();

        let idx = BaseField::from_u32_unchecked(idx_before as u32);
        let deposit_secret = poseidon_hash_pair(BaseField::from_u32_unchecked(app.deposit_secret), idx);
        let deposit_nullifier = poseidon_hash_pair(BaseField::from_u32_unchecked(app.deposit_nullifier), idx);

        tracing::info!(
            deposit_amount = app.deposit_amount,
            merkle_index = idx_before,
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

        crate::common_rpc::send_approve_tx(
            app.rpc_url.clone(),
            app.owner_private_key.clone(),
            app.max_fee_per_gas,
            app.max_priority_fee_per_gas,
            app.gas_limit,
            app.token_address,
            app.privacy_pool_address,
            U256::from(deposit_amount.0),
        )
            .await
            .expect("approve failed");

        crate::common_rpc::send_deposit_tx(
            app.rpc_url.clone(),
            app.owner_private_key.clone(),
            app.max_fee_per_gas,
            app.max_priority_fee_per_gas,
            app.gas_limit,
            app.privacy_pool_address,
            U256::from(secret_nullifier_hash.0),
            U256::from(deposit_amount.0),
            app.token_address,
        )
        .await
        .unwrap();

        // Verify deposit succeeded by checking index incremented and root matches our tree
        let idx_after = crate::common_rpc::try_call_next_leaf_index(app.rpc_url.clone(), app.privacy_pool_address)
            .await
            .unwrap_or_else(|| panic!("getNextLeafIndex unavailable after deposit"));
        let root_after = crate::common_rpc::try_call_current_root(app.rpc_url.clone(), app.privacy_pool_address)
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

        // offer1 commitment inputs
        let offer1_secret = BaseField::from_u32_unchecked(5001);
        let offer1_nullifier = BaseField::from_u32_unchecked(5002);
        let offer1_fiat_amount = common_rpc::string_to_m31("100");
        let offer1_currency_hash = common_rpc::string_to_m31("USD");
        let offer1_rev_tag_hash = common_rpc::string_to_m31("@alice");

        let offer1_inputs = OfferCreateInputs {
            secret: deposit_secret,
            nullifier: deposit_nullifier,
            deposit_amount,
            offer_amount: offer1_amount,
            refund_secret: offer1_refund_secret,
            refund_nullifier: offer1_refund_nullifier,
            refund_amount: offer1_refund_amount,
            token_address,
            merkle_siblings,
            merkle_index,
            merkle_root,
            offer_secret: offer1_secret,
            offer_nullifier: offer1_nullifier,
            fiat_amount: offer1_fiat_amount,
            currency_hash: offer1_currency_hash,
            rev_tag_hash: offer1_rev_tag_hash,
        };

        tracing::info!("Generating offer-withdraw proof");
        let offer1_proof = prove_offer_create(offer1_inputs, 8).expect("Offer proof generation failed");
        verify_offer_create(offer1_proof.clone()).expect("Offer proof verification failed");

        tracing::info!("Building on-chain verification payload");
        let offer1_verify_input =
            build_offer_onchain_verification_input(&offer1_proof).expect("Failed to build onchain input");

        tracing::info!("Calling createOffer transaction");
        let secret_hash = U256::from(12345u64.wrapping_add(idx_before));
        let currency = "USD".to_string();
        let fiat_amount = U256::from(0);
        let rev_tag = "@alice".to_string();

        send_create_offer_tx(
            &app,
            U256::from(offer1_proof.public_inputs.merkle_root.0),
            U256::from(offer1_proof.public_inputs.nullifier.0),
            app.token_address,
            U256::from(offer1_proof.public_inputs.amount.0),
            U256::from(offer1_proof.public_inputs.offer_commitment.0),
            U256::from(offer1_proof.public_inputs.refund_commitment_hash.0),
            secret_hash,
            currency,
            fiat_amount,
            rev_tag,
            &offer1_verify_input,
        )
        .await
        .expect("Failed to send createOffer transaction");

        tracing::info!("✅ Offer 1 created successfully");

        // Create second offer from first offer's refund commitment
        tracing::info!("Creating second offer from refund commitment");
        
        offchain_tree.add_leaf(offer1_proof.public_inputs.refund_commitment_hash);
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

        // offer2 commitment inputs
        let offer2_secret = BaseField::from_u32_unchecked(6001);
        let offer2_nullifier = BaseField::from_u32_unchecked(6002);
        let offer2_fiat_amount = common_rpc::string_to_m31("200");
        let offer2_currency_hash = common_rpc::string_to_m31("EUR");
        let offer2_rev_tag_hash = common_rpc::string_to_m31("@bob");

        let offer2_inputs = OfferCreateInputs {
            secret: offer1_refund_secret,
            nullifier: offer1_refund_nullifier,
            deposit_amount: offer1_refund_amount,
            offer_amount: offer2_amount_bf,
            refund_secret: offer2_refund_secret,
            refund_nullifier: offer2_refund_nullifier,
            refund_amount: offer2_refund_amount,
            token_address,
            merkle_siblings: offer2_merkle_siblings,
            merkle_index: offer2_merkle_index,
            merkle_root: offer2_merkle_root,
            offer_secret: offer2_secret,
            offer_nullifier: offer2_nullifier,
            fiat_amount: offer2_fiat_amount,
            currency_hash: offer2_currency_hash,
            rev_tag_hash: offer2_rev_tag_hash,
        };

        tracing::info!("Generating second offer proof");
        let offer2_proof = prove_offer_create(offer2_inputs, 8).expect("Offer2 proof generation failed");
        verify_offer_create(offer2_proof.clone()).expect("Offer2 proof verification failed");

        tracing::info!("Building second offer on-chain verification payload");
        let offer2_verify_input =
            build_offer_onchain_verification_input(&offer2_proof).expect("Failed to build offer2 onchain input");

        tracing::info!("Calling createOffer transaction for offer2");
        let offer2_secret = BaseField::from_u32_unchecked(77777);
        let offer2_secret_hash = poseidon_hash_pair(offer2_secret, offer2_secret);
        let secret_hash_2 = U256::from(offer2_secret_hash.0);
        let currency_2 = "EUR".to_string();
        let fiat_amount_2 = U256::from(0);
        let rev_tag_2 = "@bob".to_string();

        send_create_offer_tx(
            &app,
            U256::from(offer2_proof.public_inputs.merkle_root.0),
            U256::from(offer2_proof.public_inputs.nullifier.0),
            app.token_address,
            U256::from(offer2_proof.public_inputs.amount.0),
            U256::from(offer2_proof.public_inputs.offer_commitment.0),
            U256::from(offer2_proof.public_inputs.refund_commitment_hash.0),
            secret_hash_2,
            currency_2,
            fiat_amount_2,
            rev_tag_2,
            &offer2_verify_input,
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