use alloy::primitives::U256;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    OfferAcceptInputs, OfferCreateInputs, WithdrawInputs,
    build_offer_accept_onchain_verification_input, build_offer_onchain_verification_input,
    build_onchain_verification_input,
    prove_offer_accept, prove_offer_create, prove_withdraw,
    verify_offer_accept, verify_offer_create, verify_withdraw,
    send_withdraw_with_proof_tx,

    offchain_merkle::poseidon_hash_pair,
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use crate::common_rpc;

use self::config::AppState;

mod config;
mod tlsn;

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

        crate::common_rpc::ensure_owner_has_eth_for_gas(
            app.rpc_url.clone(),
            app.owner_private_key.clone(),
            "0x3635C9ADC5DEA000000000",
        ).await;

        let deposit_amount = BaseField::from_u32_unchecked(app.deposit_amount);
        let token_address = common_rpc::address_to_m31(app.token_address);

        // Step 1: Deposit
        let mut offchain_tree = common_rpc::build_offchain_merkle_tree(
            app.rpc_url.clone(),
            app.privacy_pool_address,
        ).await;

        let idx_before = offchain_tree.leaf_count();
        let idx = BaseField::from_u32_unchecked(idx_before as u32);
        let deposit_secret = poseidon_hash_pair(BaseField::from_u32_unchecked(app.deposit_secret), idx);
        let deposit_nullifier = poseidon_hash_pair(BaseField::from_u32_unchecked(app.deposit_nullifier), idx);

        let secret_nullifier_hash = poseidon_hash_pair(deposit_secret, deposit_nullifier);
        let secret_nullifier_amount_hash = poseidon_hash_pair(secret_nullifier_hash, deposit_amount);
        let deposit_leaf = poseidon_hash_pair(secret_nullifier_amount_hash, token_address);

        tracing::info!(
            deposit_amount = app.deposit_amount,
            merkle_index = idx_before,
            "Step 1: Depositing"
        );

        common_rpc::send_approve_tx(
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

        common_rpc::send_deposit_tx(
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
        .expect("deposit failed");

        offchain_tree.add_leaf(deposit_leaf);

        let merkle_index = u32::try_from(idx_before)
            .unwrap_or_else(|_| panic!("Leaf index does not fit u32: {idx_before}"));
        let (merkle_siblings, _) = offchain_tree.path(merkle_index as usize);
        let merkle_root = offchain_tree.root();

        let onchain_root = common_rpc::try_call_current_root(
            app.rpc_url.clone(),
            app.privacy_pool_address,
        )
        .await
        .unwrap_or_else(|| panic!("Failed to fetch on-chain root after deposit"));
        let onchain_root_u32 = u32::try_from(onchain_root)
            .unwrap_or_else(|_| panic!("On-chain root does not fit u32: {onchain_root}"));
        assert_eq!(
            merkle_root,
            BaseField::from_u32_unchecked(onchain_root_u32),
            "Off-chain merkle root mismatch after deposit: offchain={}, onchain={onchain_root}",
            merkle_root.0,
        );

        tracing::info!("✅ Step 1 done: deposit added at index {merkle_index}, root verified");

        // Step 2: Create Offer (prove deposit ∈ depositsTree)
        let offer_amount = BaseField::from_u32_unchecked(app.deposit_amount);
        let refund_amount = BaseField::from_u32_unchecked(0);

        let refund_secret = BaseField::from_u32_unchecked(2001);
        let refund_nullifier = BaseField::from_u32_unchecked(2002);

        let offer_secret = BaseField::from_u32_unchecked(5001);
        let offer_nullifier = BaseField::from_u32_unchecked(5002);
        let fiat_amount_bf = common_rpc::string_to_m31("150");
        let currency_hash = common_rpc::string_to_m31("USD");
        let rev_tag_hash = common_rpc::string_to_m31("@alice");

        let offer_inputs = OfferCreateInputs {
            secret: deposit_secret,
            nullifier: deposit_nullifier,
            deposit_amount,
            offer_amount,
            refund_secret,
            refund_nullifier,
            refund_amount,
            token_address,
            merkle_siblings,
            merkle_index,
            merkle_root,
            offer_secret,
            offer_nullifier,
            fiat_amount: fiat_amount_bf,
            currency_hash,
            rev_tag_hash,
        };

        tracing::info!("Step 2: Generating offer-create proof");
        let offer_proof = prove_offer_create(offer_inputs, 8)
            .expect("Offer proof generation failed");
        verify_offer_create(offer_proof.clone())
            .expect("Offer proof verification failed");

        let offer_verify_input = build_offer_onchain_verification_input(&offer_proof)
            .expect("Failed to build offer onchain input");

        let offer_secret_hash_bf = poseidon_hash_pair(offer_secret, offer_secret);
        let offer_secret_hash = U256::from(offer_secret_hash_bf.0);

        tracing::info!("Step 2: Calling createOffer");
        let offer_create_calldata = stwo_circuit::build_create_offer_calldata(
            U256::from(offer_proof.public_inputs.merkle_root.0),
            U256::from(offer_proof.public_inputs.nullifier.0),
            app.token_address,
            U256::from(offer_proof.public_inputs.amount.0),
            U256::from(offer_proof.public_inputs.offer_commitment.0),
            U256::from(offer_proof.public_inputs.refund_commitment_hash.0),
            offer_secret_hash,
            "USD".to_string(),
            U256::from(150u64),
            "@alice".to_string(),
            &offer_verify_input,
        );
        common_rpc::send_simple_tx(
            app.rpc_url.clone(),
            app.owner_private_key.clone(),
            app.max_fee_per_gas,
            app.max_priority_fee_per_gas,
            app.gas_limit,
            app.privacy_pool_address,
            offer_create_calldata.into(),
            "createOffer",
        )
        .await
        .expect("createOffer failed");

        tracing::info!("✅ Step 2 done: offer created, offer_commitment = {}", offer_proof.public_inputs.offer_commitment.0);

        // Step 3: Build off-chain offersTree from OfferCreated events
        tracing::info!("Step 3: Building off-chain offersTree");
        let offers_tree = common_rpc::build_offchain_offers_tree(
            app.rpc_url.clone(),
            app.privacy_pool_address,
        ).await;
        let offer_commitment_leaf = offer_proof.public_inputs.offer_commitment;

        let offers_merkle_index = offers_tree
            .find_leaf_index(offer_commitment_leaf)
            .unwrap_or_else(|| panic!("offer_commitment not found in offersTree"))
            as u32;

        let (offers_merkle_siblings, _) = offers_tree.path(offers_merkle_index as usize);
        let offers_merkle_root = offers_tree.root();

        tracing::info!("Offer commitment found at offersTree index {offers_merkle_index}");

        // Step 4: Cancel Offer (prove offer_commitment ∈ offersTree)
        let output_secret = BaseField::from_u32_unchecked(7001);
        let output_nullifier = BaseField::from_u32_unchecked(7002);

        let cancel_inputs = OfferAcceptInputs {
            offer_secret,
            offer_nullifier,
            offer_amount,
            token_address,
            fiat_amount: fiat_amount_bf,
            currency_hash,
            rev_tag_hash,
            offers_merkle_siblings,
            offers_merkle_index,
            offers_merkle_root,
            output_secret,
            output_nullifier,
        };

        tracing::info!("Step 4: Generating cancel proof");
        let cancel_proof = prove_offer_accept(cancel_inputs, 8)
            .expect("Cancel proof generation failed");
        verify_offer_accept(cancel_proof.clone())
            .expect("Cancel proof verification failed");

        let cancel_verify_input = build_offer_accept_onchain_verification_input(&cancel_proof)
            .expect("Failed to build cancel onchain input");

        tracing::info!("Step 4: Calling cancelOffer");
        let cancel_offer_calldata = stwo_circuit::build_cancel_offer_calldata(
            U256::from(cancel_proof.public_inputs.offers_merkle_root.0),
            U256::from(cancel_proof.public_inputs.nullifier.0),
            app.token_address,
            U256::from(cancel_proof.public_inputs.amount.0),
            U256::from(cancel_proof.public_inputs.offer_commitment.0),
            U256::from(cancel_proof.public_inputs.output_commitment.0),
            &cancel_verify_input,
        );
        common_rpc::send_simple_tx(
            app.rpc_url.clone(),
            app.owner_private_key.clone(),
            app.max_fee_per_gas,
            app.max_priority_fee_per_gas,
            app.gas_limit,
            app.privacy_pool_address,
            cancel_offer_calldata.into(),
            "cancelOffer",
        )
        .await
        .expect("cancelOffer failed");

        tracing::info!(
            output_commitment = cancel_proof.public_inputs.output_commitment.0,
            "✅ Step 4 done: offer cancelled, new deposit created in depositsTree"
        );

        // Step 5: Withdraw the output_commitment from depositsTree
        tracing::info!("Step 5: Building off-chain depositsTree for withdraw");
        let withdraw_tree = common_rpc::build_offchain_merkle_tree(
            app.rpc_url.clone(),
            app.privacy_pool_address,
        ).await;

        let output_leaf = cancel_proof.public_inputs.output_commitment;
        let withdraw_merkle_index = withdraw_tree
            .find_leaf_index(output_leaf)
            .unwrap_or_else(|| panic!("output_commitment not found in depositsTree"))
            as u32;
        let (withdraw_siblings, _) = withdraw_tree.path(withdraw_merkle_index as usize);
        let withdraw_merkle_root = withdraw_tree.root();

        tracing::info!("Output commitment found at depositsTree index {withdraw_merkle_index}");

        tracing::info!("Step 5a: Running TLSN to get balance commitment from server");
        let (balance_fragment, blinder, commitment_hash) =
            tlsn::run_tlsn_balance_query(&app).await;
        let tlsn_amount = tlsn::parse_amount_from_fragment(&balance_fragment);
        tracing::info!(tlsn_amount, "Amount extracted from TLSN committed fragment");

        let withdraw_amount = BaseField::from_u32_unchecked(tlsn_amount);
        let refund_amount_u32 = offer_amount
            .0
            .checked_sub(tlsn_amount)
            .unwrap_or_else(|| panic!("TLSN amount {tlsn_amount} exceeds offer amount {}", offer_amount.0));
        let refund_amount = BaseField::from_u32_unchecked(refund_amount_u32);

        let withdraw_inputs = WithdrawInputs {
            balance_fragment,
            blinder,
            commitment_hash,
            secret: output_secret,
            nullifier: output_nullifier,
            commitment_amount: offer_amount,
            withdraw_amount,
            refund_secret: BaseField::from_u32_unchecked(8001),
            refund_nullifier: BaseField::from_u32_unchecked(8002),
            refund_amount,
            token_address,
            merkle_siblings: withdraw_siblings,
            merkle_index: withdraw_merkle_index,
            merkle_root: withdraw_merkle_root,
        };

        tracing::info!("Step 5: Generating withdraw proof");
        let withdraw_proof = prove_withdraw(withdraw_inputs, 8)
            .expect("Withdraw proof generation failed");
        verify_withdraw(withdraw_proof.clone())
            .expect("Withdraw proof off-chain verification failed");

        let withdraw_verify_input = build_onchain_verification_input(&withdraw_proof)
            .expect("Failed to build withdraw onchain input");

        let recipient_balance_before = common_rpc::get_erc20_balance(
            app.rpc_url.clone(),
            app.token_address,
            app.withdraw_recipient,
        ).await;

        tracing::info!("Step 5: Calling withdraw");
        let tx_hash = send_withdraw_with_proof_tx(
            &app.rpc_url,
            &app.owner_private_key,
            app.privacy_pool_address,
            app.gas_limit,
            U256::from(withdraw_proof.public_inputs.merkle_root.0),
            U256::from(withdraw_proof.public_inputs.nullifier.0),
            app.token_address,
            U256::from(withdraw_proof.public_inputs.amount.0),
            app.withdraw_recipient,
            U256::from(withdraw_proof.public_inputs.refund_commitment_hash.0),
            &withdraw_verify_input,
        )
        .await
        .expect("Withdraw transaction failed");

        let recipient_balance_after = common_rpc::get_erc20_balance(
            app.rpc_url.clone(),
            app.token_address,
            app.withdraw_recipient,
        ).await;
        let expected_delta = U256::from(withdraw_proof.public_inputs.amount.0);
        assert_eq!(
            recipient_balance_after,
            recipient_balance_before + expected_delta,
            "Recipient balance did not increase by expected amount: before={recipient_balance_before}, after={recipient_balance_after}, expected_delta={expected_delta}"
        );

        tracing::info!(
            %tx_hash,
            delta = %expected_delta,
            "✅ Step 5 done: withdrawal completed, recipient balance increased"
        );

        tracing::info!("✅ Full E2E passed: deposit -> createOffer -> cancelOffer -> withdraw");
    });
}