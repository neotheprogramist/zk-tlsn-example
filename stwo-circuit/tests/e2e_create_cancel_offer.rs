use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use base64::Engine;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, prove_circuit_assignment};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::QM31},
        pcs::TreeVec,
    },
    prover::backend::simd::SimdBackend,
};
use stwo_circuit::{
    offchain_merkle::{OffchainMerkleTree, poseidon_hash_pair},
    paymoney_circuits::offer_circuit::build_offer_merkle_context_from_offchain_tree,
    paymoney_circuits::offer_spend_cancel_circuit::build_offer_spend_cancel_context_from_offchain_tree,
};
use trusted_stwo_server::types::{VerifyAndSignRequest, VerifyAndSignResponse};

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    interface IPrivacyPool {
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function createOffer(
            uint32[4][] calldata claimOutputValues,
            bytes calldata signature,
            address token,
            uint256 secretHash
        ) external;
        function cancelOffer(
            uint32[4][] calldata claimOutputValues,
            bytes calldata signature,
            address token,
            uint256 offerCommitment,
            uint256 outputCommitment
        ) external;
        function withdraw(
            uint256 root,
            uint256 nullifier,
            uint256 amount,
            uint256 refundCommitmentHash,
            bytes calldata signature,
            address token,
            address recipient
        ) external;
        function getCurrentRoot() external view returns (uint256);
        function getOffersTreeRoot() external view returns (uint256);
        function isNullifierUsed(uint256 nullifier) external view returns (bool);
        function isOfferNullifierUsed(uint256 nullifier) external view returns (bool);
    }
}

const RPC_URL: &str = "http://127.0.0.1:8545";
const PRIVACY_POOL_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TOKEN_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const OWNER_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const M31_MODULUS: u32 = 2_147_483_647;
const TRUSTED_SERVER_PRIVATE_KEY_HEX: &str =
    "a731c83a8c388ff4a8bd05c429ca250ca09c8a444c8110515db297379899ce8b";

fn qm31_to_u32s(value: QM31) -> [u32; 4] {
    let limbs = value.to_m31_array();
    [limbs[0].0, limbs[1].0, limbs[2].0, limbs[3].0]
}

fn address_to_m31(address: Address) -> BaseField {
    let address_u256 = U256::from_be_slice(address.as_slice());
    let reduced = address_u256 % U256::from(M31_MODULUS);
    let reduced_u32 = u32::try_from(reduced).expect("address modulo M31 fits u32");
    BaseField::from_u32_unchecked(reduced_u32)
}

fn m31_from_output(values: &[[u32; 4]], index: usize) -> u32 {
    let limbs = values
        .get(index)
        .unwrap_or_else(|| panic!("missing claim output at index {index}"));
    assert_eq!(limbs[1], 0, "output[{index}] is not scalar QM31");
    assert_eq!(limbs[2], 0, "output[{index}] is not scalar QM31");
    assert_eq!(limbs[3], 0, "output[{index}] is not scalar QM31");
    limbs[0]
}

async fn send_tx(
    provider: &impl Provider,
    to: Address,
    input: Bytes,
    label: &str,
) -> Result<(), String> {
    let tx = TransactionRequest::default().to(to).input(input.into());
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| format!("{label} send failed: {e}"))?;
    let tx_hash = *pending.tx_hash();
    let receipt = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        pending.get_receipt(),
    )
    .await
    .map_err(|_| {
        format!(
            "{label} receipt timeout (30 s): tx {} was sent but never mined — \
             possible nonce gap or mempool rejection",
            tx_hash
        )
    })?
    .map_err(|e| format!("{label} receipt failed: {e}"))?;
    if !receipt.status() {
        return Err(format!(
            "{label} reverted, tx={}, gas_used={:?}",
            receipt.transaction_hash, receipt.gas_used
        ));
    }
    Ok(())
}

async fn erc20_balance(
    provider: &impl Provider,
    token: Address,
    account: Address,
) -> Result<U256, String> {
    let calldata = IERC20::balanceOfCall { account }.abi_encode();
    let raw = provider
        .call(TransactionRequest::default().to(token).input(calldata.into()))
        .await
        .map_err(|e| format!("balanceOf eth_call failed: {e}"))?;
    IERC20::balanceOfCall::abi_decode_returns(&raw)
        .map_err(|e| format!("balanceOf decode failed: {e}"))
}

async fn current_root(provider: &impl Provider, pool: Address) -> Result<U256, String> {
    let calldata = IPrivacyPool::getCurrentRootCall {}.abi_encode();
    let raw = provider
        .call(TransactionRequest::default().to(pool).input(calldata.into()))
        .await
        .map_err(|e| format!("getCurrentRoot eth_call failed: {e}"))?;
    IPrivacyPool::getCurrentRootCall::abi_decode_returns(&raw)
        .map_err(|e| format!("getCurrentRoot decode failed: {e}"))
}

/// Build deposits offchain tree by replaying Deposit events.
async fn build_deposits_tree(provider: &impl Provider, pool: Address) -> OffchainMerkleTree {
    let mut tree = OffchainMerkleTree::new(31);
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .from_block(0u64)
                .event("Deposit(uint256,uint256,address,uint64,uint256)"),
        )
        .await
        .expect("fetch Deposit logs");
    for log in logs {
        let topic = log.inner.topics().get(1).expect("Deposit commitment topic");
        let val = u32::try_from(U256::from_be_slice(topic.as_slice()))
            .expect("deposit commitment fits u32");
        tree.add_leaf(BaseField::from_u32_unchecked(val));
    }
    tree
}

/// Build offers offchain tree by replaying OfferCreated and RecursiveOfferCreated events.
async fn build_offers_tree(provider: &impl Provider, pool: Address) -> OffchainMerkleTree {
    let mut tree = OffchainMerkleTree::new(31);

    let mut logs: Vec<_> = {
        let single = provider
            .get_logs(
                &Filter::new()
                    .address(pool)
                    .from_block(0u64)
                    .event("OfferCreated(uint256,uint256,address,uint256)"),
            )
            .await
            .expect("fetch OfferCreated logs");
        let recursive = provider
            .get_logs(
                &Filter::new()
                    .address(pool)
                    .from_block(0u64)
                    .event("RecursiveOfferCreated(uint256,uint256,address,uint256,uint256)"),
            )
            .await
            .expect("fetch RecursiveOfferCreated logs");
        single.into_iter().chain(recursive).collect()
    };

    logs.sort_by_key(|l| (l.block_number.unwrap_or(0), l.log_index.unwrap_or(0)));

    for log in logs {
        let topic = log.inner.topics().get(1).expect("offer commitment topic");
        let val = u32::try_from(U256::from_be_slice(topic.as_slice()))
            .expect("offerCommitment fits u32");
        tree.add_leaf(BaseField::from_u32_unchecked(val));
    }
    tree
}

/// Send a ZK proof to the trusted server and return the signed response.
async fn verify_and_sign(
    trusted_server_url: &str,
    payload: &VerifyAndSignRequest,
    label: &str,
) -> VerifyAndSignResponse {
    let resp = reqwest::Client::new()
        .post(format!("{trusted_server_url}/verify-and-sign"))
        .json(payload)
        .send()
        .await
        .unwrap_or_else(|e| panic!("{label} request failed: {e}"));
    let status = resp.status();
    let body = resp
        .text()
        .await
        .unwrap_or_else(|e| panic!("{label} read body failed: {e}"));
    assert!(
        status.is_success(),
        "{label} rejected by trusted server: status={status}, body={body}"
    );
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{label} parse response failed: {e}, body={body}"))
}

fn prove_and_build_payload(
    ctx: &mut circuits::context::Context<QM31>,
    proof_id: String,
) -> VerifyAndSignRequest {
    let preprocessed = PreprocessedCircuit::preprocess_circuit(ctx);
    let proof = prove_circuit_assignment(
        ctx.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    let stark = proof.stark_proof.expect("stark proof");
    let sizes = TreeVec::concat_cols(proof.components.iter().map(|c| c.trace_log_degree_bounds()));

    VerifyAndSignRequest {
        proof_id,
        pcs_config_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&proof.pcs_config).expect("serialize pcs")),
        stark_proof_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&stark).expect("serialize stark")),
        channel_salt: proof.channel_salt,
        interaction_pow_nonce: proof.interaction_pow_nonce,
        claim_log_sizes: proof.claim.log_sizes.to_vec(),
        claim_output_values: proof
            .claim
            .output_values
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        interaction_claimed_sums: proof
            .interaction_claim
            .claimed_sums
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        stage1_trace_log_sizes: sizes[1].clone(),
        stage2_trace_log_sizes: sizes[2].clone(),
        preprocessed_trace_log_sizes: preprocessed.preprocessed_trace.log_sizes(),
        preprocessed_column_ids: preprocessed
            .preprocessed_trace
            .ids()
            .iter()
            .map(|id| id.id.clone())
            .collect(),
        output_addresses: preprocessed.params.output_addresses.clone(),
        n_blake_gates: preprocessed.params.n_blake_gates,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_create_cancel_offer() {
    let pool: Address = PRIVACY_POOL_ADDRESS.parse().expect("pool address");
    let token: Address = TOKEN_ADDRESS.parse().expect("token address");

    let signer: PrivateKeySigner = OWNER_PRIVATE_KEY.parse().expect("owner key");
    let owner_addr = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(RPC_URL.parse().expect("rpc url"));

    let trusted_server_url =
        std::env::var("TRUSTED_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos() as u64;

    let nonce_m31 = |salt: u64| -> BaseField {
        let v = (((run_nonce ^ salt) % ((M31_MODULUS as u64) - 1)) + 1) as u32;
        BaseField::from_u32_unchecked(v)
    };
    let str_to_m31 = |s: &str| -> BaseField {
        let h = s
            .bytes()
            .fold(0u64, |acc, b| (acc.wrapping_mul(131) + b as u64) % M31_MODULUS as u64);
        BaseField::from_u32_unchecked(h as u32)
    };

    // ── 1. Deposit ────────────────────────────────────────────────────────────
    let deposit_secret = nonce_m31(0x1000_0001);
    let deposit_nullifier = nonce_m31(0x1000_0002);
    let token_m31 = address_to_m31(token);
    let deposit_amount = BaseField::from_u32_unchecked(100);
    let offer_amount = BaseField::from_u32_unchecked(60);
    let offer_change_amount = BaseField::from_u32_unchecked(40); // deposit_amount - offer_amount

    let deposit_sn_hash = poseidon_hash_pair(deposit_secret, deposit_nullifier);

    send_tx(
        &provider,
        token,
        IERC20::approveCall {
            spender: pool,
            amount: U256::from(deposit_amount.0 as u64),
        }
        .abi_encode()
        .into(),
        "approve",
    )
    .await
    .expect("approve");

    send_tx(
        &provider,
        pool,
        IPrivacyPool::depositCall {
            secretNullifierHash: U256::from(deposit_sn_hash.0 as u64),
            amount: U256::from(deposit_amount.0 as u64),
            token,
        }
        .abi_encode()
        .into(),
        "deposit",
    )
    .await
    .expect("deposit");

    let deposits_tree = build_deposits_tree(&provider, pool).await;
    let deposits_root_u32 = u32::try_from(
        current_root(&provider, pool).await.expect("current root"),
    )
    .expect("root fits u32");
    assert_eq!(
        deposits_tree.root().0,
        deposits_root_u32,
        "deposits offchain tree root mismatch"
    );

    // ── 2. createOffer — consume deposit, put offer into offersTree ───────────
    let offer_secret = nonce_m31(0x2000_0001);
    let offer_nullifier = nonce_m31(0x2000_0002);
    let fiat_amount = BaseField::from_u32_unchecked(200);
    let currency_hash = str_to_m31("PLN");
    let rev_tag_hash = str_to_m31("@sellerrevtag");

    // post-use seller refund key — embedded in offerCommitment
    let post_use_refund_secret = nonce_m31(0x3000_0001);
    let post_use_refund_nullifier = nonce_m31(0x3000_0002);
    // initial change from deposit split
    let change_secret = nonce_m31(0x4000_0001);
    let change_nullifier = nonce_m31(0x4000_0002);

    let mut offer_ctx = build_offer_merkle_context_from_offchain_tree(
        &deposits_tree,
        deposit_secret,
        deposit_nullifier,
        deposit_amount,
        token_m31,
        offer_amount,
        offer_secret,
        offer_nullifier,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        post_use_refund_secret,
        post_use_refund_nullifier,
        change_secret,
        change_nullifier,
        offer_change_amount,
    )
    .expect("build offer circuit context");
    offer_ctx.finalize_guessed_vars();
    offer_ctx.validate_circuit();

    let offer_payload = prove_and_build_payload(
        &mut offer_ctx,
        format!("e2e-cancel-offer-create-{run_nonce}"),
    );
    let offer_sign = verify_and_sign(&trusted_server_url, &offer_payload, "createOffer sign").await;
    assert!(offer_sign.verified, "offer circuit not verified");

    // offer_circuit outputs: [0] depositsRoot [1] nullifier [2] token [3] amount
    //                        [4] offerCommitment [5] refundCommitment [6] offerRefundSnHash
    let offer_commitment_u32 = m31_from_output(&offer_payload.claim_output_values, 4);
    let offer_secret_hash = poseidon_hash_pair(offer_secret, offer_secret);

    send_tx(
        &provider,
        pool,
        IPrivacyPool::createOfferCall {
            claimOutputValues: offer_payload.claim_output_values.clone(),
            signature: Bytes::from(
                hex::decode(offer_sign.signature_hex.trim_start_matches("0x"))
                    .expect("offer signature hex"),
            ),
            token,
            secretHash: U256::from(offer_secret_hash.0 as u64),
        }
        .abi_encode()
        .into(),
        "createOffer",
    )
    .await
    .expect("createOffer");

    // ── 3. cancelOffer — prove offersTree membership, nullify offer ───────────
    let offers_tree = build_offers_tree(&provider, pool).await;
    assert_eq!(
        offers_tree.root().0,
        {
            let raw = provider
                .call(
                    TransactionRequest::default()
                        .to(pool)
                        .input(IPrivacyPool::getOffersTreeRootCall {}.abi_encode().into()),
                )
                .await
                .expect("getOffersTreeRoot call");
            let root_u256 = IPrivacyPool::getOffersTreeRootCall::abi_decode_returns(&raw)
                .expect("decode offersTreeRoot");
            u32::try_from(root_u256).expect("offersRoot fits u32")
        },
        "offers offchain tree root mismatch"
    );
    println!(
        "offers tree root = {}, leaf count = {}",
        offers_tree.root().0,
        offers_tree.leaf_count()
    );

    let mut cancel_ctx = build_offer_spend_cancel_context_from_offchain_tree(
        &offers_tree,
        offer_secret,
        offer_nullifier,
        offer_amount,
        token_m31,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        post_use_refund_secret,
        post_use_refund_nullifier,
    )
    .expect("build offer_spend_cancel context from offchain offers tree");
    cancel_ctx.finalize_guessed_vars();
    cancel_ctx.validate_circuit();

    let cancel_payload = prove_and_build_payload(
        &mut cancel_ctx,
        format!("e2e-cancel-offer-cancel-{run_nonce}"),
    );
    let cancel_sign =
        verify_and_sign(&trusted_server_url, &cancel_payload, "cancelOffer sign").await;
    assert!(cancel_sign.verified, "cancel circuit not verified");

    // cancel_circuit outputs: [0] offersRoot [1] offerNullifierHash [2] token
    //                         [3] amount [4] offerCommitment [5] outputCommitment
    let cancel_offer_commitment_u32 = m31_from_output(&cancel_payload.claim_output_values, 4);
    let cancel_output_commitment_u32 = m31_from_output(&cancel_payload.claim_output_values, 5);
    let cancel_offer_nullifier_u32 = m31_from_output(&cancel_payload.claim_output_values, 1);

    assert_eq!(
        cancel_offer_commitment_u32, offer_commitment_u32,
        "cancel circuit's offerCommitment must match the one placed on-chain"
    );

    // ── Invariant: offer nullifier not yet used ───────────────────────────────
    let raw = provider
        .call(
            TransactionRequest::default()
                .to(pool)
                .input(
                    IPrivacyPool::isOfferNullifierUsedCall {
                        nullifier: U256::from(cancel_offer_nullifier_u32 as u64),
                    }
                    .abi_encode()
                    .into(),
                ),
        )
        .await
        .expect("isOfferNullifierUsed call");
    let is_used = IPrivacyPool::isOfferNullifierUsedCall::abi_decode_returns(&raw)
        .expect("decode isOfferNullifierUsed");
    assert!(!is_used, "offer nullifier should not be used before cancel");

    send_tx(
        &provider,
        pool,
        IPrivacyPool::cancelOfferCall {
            claimOutputValues: cancel_payload.claim_output_values.clone(),
            signature: Bytes::from(
                hex::decode(cancel_sign.signature_hex.trim_start_matches("0x"))
                    .expect("cancel signature hex"),
            ),
            token,
            offerCommitment: U256::from(cancel_offer_commitment_u32 as u64),
            outputCommitment: U256::from(cancel_output_commitment_u32 as u64),
        }
        .abi_encode()
        .into(),
        "cancelOffer",
    )
    .await
    .expect("cancelOffer");

    // ── Invariant: offer nullifier is now used ─────────────────────────────────
    let raw2 = provider
        .call(
            TransactionRequest::default()
                .to(pool)
                .input(
                    IPrivacyPool::isOfferNullifierUsedCall {
                        nullifier: U256::from(cancel_offer_nullifier_u32 as u64),
                    }
                    .abi_encode()
                    .into(),
                ),
        )
        .await
        .expect("isOfferNullifierUsed call after cancel");
    let is_used_after = IPrivacyPool::isOfferNullifierUsedCall::abi_decode_returns(&raw2)
        .expect("decode isOfferNullifierUsed after");
    assert!(
        is_used_after,
        "offer nullifier must be marked used after cancelOffer"
    );

    // ── 4. Seller withdraws the refund deposit created by cancelOffer ─────────
    // The outputCommitment = H(H(offer_refund_sn_hash, amount), token) is now in deposits tree.
    // Seller can withdraw it using withdraw_circuit. Here we just verify the balance increased.
    let owner_balance_before = erc20_balance(&provider, token, owner_addr)
        .await
        .expect("owner balance before withdraw");

    // Build the withdraw proof for the seller's cancel refund.
    // The refund deposit uses post_use_refund_secret/nullifier as keys.
    let cancel_deposits_tree = build_deposits_tree(&provider, pool).await;
    let cancel_root_u32 =
        u32::try_from(current_root(&provider, pool).await.expect("deposits root"))
            .expect("root fits u32");
    assert_eq!(
        cancel_deposits_tree.root().0,
        cancel_root_u32,
        "deposits tree mismatch after cancel"
    );

    use stwo_circuit::paymoney_circuits::withdraw_circuit::build_withdraw_merkle_context_from_offchain_tree;

    // post_use_refund deposit: amount = offer_amount, commitment = outputCommitment
    // withdraw full amount, no further refund
    let withdraw_refund_secret = nonce_m31(0x5000_0001);
    let withdraw_refund_nullifier = nonce_m31(0x5000_0002);
    let withdraw_recipient_m31 = address_to_m31(owner_addr);

    let mut withdraw_ctx = build_withdraw_merkle_context_from_offchain_tree(
        &cancel_deposits_tree,
        post_use_refund_secret,
        post_use_refund_nullifier,
        offer_amount,
        token_m31,
        offer_amount, // withdraw full amount
        withdraw_refund_secret,
        withdraw_refund_nullifier,
        BaseField::from_u32_unchecked(0), // no refund remainder
        withdraw_recipient_m31,
    )
    .expect("build withdraw context for seller cancel refund");
    withdraw_ctx.finalize_guessed_vars();
    withdraw_ctx.validate_circuit();

    let withdraw_payload = prove_and_build_payload(
        &mut withdraw_ctx,
        format!("e2e-cancel-offer-withdraw-{run_nonce}"),
    );
    let withdraw_sign =
        verify_and_sign(&trusted_server_url, &withdraw_payload, "withdraw sign").await;
    assert!(withdraw_sign.verified, "withdraw circuit not verified");

    let w_root = U256::from(m31_from_output(&withdraw_payload.claim_output_values, 0) as u64);
    let w_nullifier = U256::from(m31_from_output(&withdraw_payload.claim_output_values, 1) as u64);
    let w_amount = U256::from(m31_from_output(&withdraw_payload.claim_output_values, 3) as u64);
    let w_refund_commitment =
        U256::from(m31_from_output(&withdraw_payload.claim_output_values, 4) as u64);

    send_tx(
        &provider,
        pool,
        IPrivacyPool::withdrawCall {
            root: w_root,
            nullifier: w_nullifier,
            amount: w_amount,
            refundCommitmentHash: w_refund_commitment,
            signature: Bytes::from(
                hex::decode(withdraw_sign.signature_hex.trim_start_matches("0x"))
                    .expect("withdraw signature hex"),
            ),
            token,
            recipient: owner_addr,
        }
        .abi_encode()
        .into(),
        "withdraw seller refund",
    )
    .await
    .expect("withdraw seller cancel refund");

    let owner_balance_after = erc20_balance(&provider, token, owner_addr)
        .await
        .expect("owner balance after withdraw");

    assert_eq!(
        owner_balance_after,
        owner_balance_before + U256::from(offer_amount.0 as u64),
        "seller should receive full offer_amount after cancel+withdraw"
    );
    let _ = TRUSTED_SERVER_PRIVATE_KEY_HEX; // only used in other tests that sign directly
}
