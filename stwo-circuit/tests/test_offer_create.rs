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
};
use trusted_stwo_server::types::{VerifyAndSignRequest, VerifyAndSignResponse};

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    interface IPrivacyPool {
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function createOffer(
            uint32[4][] calldata claimOutputValues,
            bytes calldata signature,
            address token,
            uint256 secretHash
        ) external;
        function getCurrentRoot() external view returns (uint256);
    }
}

const RPC_URL: &str = "http://127.0.0.1:8545";
const PRIVACY_POOL_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TOKEN_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const OWNER_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const M31_MODULUS: u32 = 2_147_483_647;

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

fn m31_from_claim_output(values: &[[u32; 4]], index: usize) -> u32 {
    let limbs = values
        .get(index)
        .unwrap_or_else(|| panic!("missing claim output at index {index}"));
    assert_eq!(limbs[1], 0);
    assert_eq!(limbs[2], 0);
    assert_eq!(limbs[3], 0);
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
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| format!("{label} receipt failed: {e}"))?;
    if !receipt.status() {
        return Err(format!(
            "{label} reverted, tx={}, gas_used={:?}",
            receipt.transaction_hash, receipt.gas_used
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_offer_create_server_sign_real_chain() {
    let rpc_url = RPC_URL.to_string();
    let pool: Address = PRIVACY_POOL_ADDRESS.parse().expect("valid pool address");
    let token: Address = TOKEN_ADDRESS.parse().expect("valid token address");

    let signer: PrivateKeySigner = OWNER_PRIVATE_KEY.parse().expect("valid owner private key");
    let provider = ProviderBuilder::new().wallet(signer).connect_http(
        rpc_url.parse().expect("valid rpc url"),
    );

    let mut offchain_tree = OffchainMerkleTree::new(31);
    let historical_logs = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .from_block(0u64)
                .event("Deposit(uint256,uint256,address,uint64,uint256)"),
        )
        .await
        .expect("fetch historical deposit logs");
    for log in historical_logs {
        let commitment_topic = log
            .inner
            .topics()
            .get(1)
            .expect("deposit commitment topic must exist");
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256)
            .expect("deposit commitment should fit M31/u32");
        offchain_tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }

    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos() as u64;
    let nonce_m31 = |salt: u64| -> BaseField {
        let v = (((run_nonce ^ salt) % ((M31_MODULUS as u64) - 1)) + 1) as u32;
        BaseField::from_u32_unchecked(v)
    };
    let str_to_m31 = |s: &str| -> BaseField {
        let h = s.bytes().fold(0u64, |acc, b| (acc.wrapping_mul(131) + b as u64) % M31_MODULUS as u64);
        BaseField::from_u32_unchecked(h as u32)
    };

    let secret = nonce_m31(0x1111_0001);
    let nullifier = nonce_m31(0x1111_0002);
    let token_m31 = address_to_m31(token);

    let deposit_amount = BaseField::from_u32_unchecked(100);
    let offer_amount = BaseField::from_u32_unchecked(70);
    let refund_amount = BaseField::from_u32_unchecked(30);
    let commitment_amount = deposit_amount;

    let secret_nullifier_hash = poseidon_hash_pair(secret, nullifier);

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
    .expect("approve tx");

    let deposit_start_block = provider
        .get_block_number()
        .await
        .expect("get block number before deposit");
    send_tx(
        &provider,
        pool,
        IPrivacyPool::depositCall {
            secretNullifierHash: U256::from(secret_nullifier_hash.0 as u64),
            amount: U256::from(deposit_amount.0 as u64),
            token,
        }
        .abi_encode()
        .into(),
        "deposit",
    )
    .await
    .expect("deposit tx");

    let mut new_logs = Vec::new();
    for _ in 0..20 {
        let logs = provider
            .get_logs(
                &Filter::new()
                    .address(pool)
                    .from_block(deposit_start_block)
                    .event("Deposit(uint256,uint256,address,uint64,uint256)"),
            )
            .await
            .expect("fetch deposit logs");
        if !logs.is_empty() {
            new_logs = logs;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    assert!(!new_logs.is_empty(), "expected Deposit event after deposit tx");

    new_logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });
    for log in new_logs {
        let commitment_topic = log.inner.topics().get(1).expect("deposit commitment topic");
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256)
            .expect("deposit commitment should fit M31/u32");
        offchain_tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }

    let offer_secret = nonce_m31(0x2222_0001);
    let offer_nullifier = nonce_m31(0x2222_0002);
    let fiat_amount = BaseField::from_u32_unchecked(500);
    let currency_hash = str_to_m31("PLN");
    let rev_tag_hash = str_to_m31("testrevtag");
    let offer_refund_secret = nonce_m31(0x4444_0001);
    let offer_refund_nullifier = nonce_m31(0x4444_0002);
    let refund_secret = nonce_m31(0x3333_0001);
    let refund_nullifier = nonce_m31(0x3333_0002);

    let mut context = build_offer_merkle_context_from_offchain_tree(
        &offchain_tree,
        secret,
        nullifier,
        commitment_amount,
        token_m31,
        offer_amount,
        offer_secret,
        offer_nullifier,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        offer_refund_secret,
        offer_refund_nullifier,
        refund_secret,
        refund_nullifier,
        refund_amount,
    )
    .expect("build offer context from offchain tree");

    context.finalize_guessed_vars();
    context.validate_circuit();

    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    let proof = prove_circuit_assignment(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    assert!(proof.stark_proof.is_ok(), "proof generation failed");
    let stark_proof = proof.stark_proof.expect("stark proof");

    let sizes = TreeVec::concat_cols(proof.components.iter().map(|c| c.trace_log_degree_bounds()));

    let payload = VerifyAndSignRequest {
        proof_id: format!("e2e-offer-create-{run_nonce}"),
        pcs_config_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&proof.pcs_config).expect("serialize pcs config")),
        stark_proof_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&stark_proof).expect("serialize stark proof")),
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
    };

    let trusted_server_url = std::env::var("TRUSTED_SERVER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    let sign_resp = reqwest::Client::new()
        .post(format!("{trusted_server_url}/verify-and-sign"))
        .json(&payload)
        .send()
        .await
        .expect("trusted server request failed");
    assert_eq!(sign_resp.status(), reqwest::StatusCode::OK);

    let parsed: VerifyAndSignResponse = sign_resp.json().await.expect("decode response");
    assert!(parsed.verified);

    // Note: secretHash in contract is H(secret, secret), same as circuit binding.
    let secret_hash = poseidon_hash_pair(secret, secret);

    send_tx(
        &provider,
        pool,
        IPrivacyPool::createOfferCall {
            claimOutputValues: payload.claim_output_values.clone(),
            signature: Bytes::from(
                hex::decode(parsed.signature_hex.trim_start_matches("0x"))
                    .expect("signature hex"),
            ),
            token,
            secretHash: U256::from(secret_hash.0 as u64),
        }
        .abi_encode()
        .into(),
        "createOffer",
    )
    .await
    .expect("createOffer tx should succeed");

    // Root from claim output[0] should still be a valid historical root after tx.
    let onchain_root = provider
        .call(TransactionRequest::default().to(pool).input(IPrivacyPool::getCurrentRootCall {}.abi_encode().into()))
        .await
        .expect("get root call");
    let decoded = IPrivacyPool::getCurrentRootCall::abi_decode_returns(&onchain_root)
        .expect("decode root");
    let claim_root = U256::from(m31_from_claim_output(&payload.claim_output_values, 0) as u64);
    assert!(decoded != U256::ZERO);
    assert!(claim_root != U256::ZERO);
}
