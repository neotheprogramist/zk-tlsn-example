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
use circuits::blake::HashValue;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::QM31},
        pcs::TreeVec,
    },
    prover::backend::simd::SimdBackend,
};
use stwo_circuit::{
    offchain_merkle::{OffchainMerkleTree, poseidon_hash_pair},
    paymoney_circuits::withdraw_circuit::build_withdraw_merkle_context_from_offchain_tree,
};
use trusted_stwo_server::types::{VerifyAndSignRequest, VerifyAndSignResponse};

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    interface IPrivacyPool {
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function withdraw(
            uint256 root,
            uint256 nullifier,
            uint256 amount,
            uint256 refundCommitmentHash,
            bytes calldata signature,
            address token,
            address recipient
        ) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
    }
}

const RPC_URL: &str = "http://127.0.0.1:8545";
const PRIVACY_POOL_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TOKEN_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const OWNER_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RECIPIENT_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
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
    assert_eq!(limbs[1], 0, "claim output[{index}] limb[1] must be zero");
    assert_eq!(limbs[2], 0, "claim output[{index}] limb[2] must be zero");
    assert_eq!(limbs[3], 0, "claim output[{index}] limb[3] must be zero");
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

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_deposit_server_sign_withdraw_real_chain() {
    let rpc_url = RPC_URL.to_string();
    let pool: Address = PRIVACY_POOL_ADDRESS.parse().expect("valid pool address");
    let token: Address = TOKEN_ADDRESS.parse().expect("valid token address");
    let recipient: Address = RECIPIENT_ADDRESS.parse().expect("valid recipient address");

    let signer: PrivateKeySigner = OWNER_PRIVATE_KEY.parse().expect("valid owner private key");
    let owner_addr = signer.address();
    let provider = ProviderBuilder::new().wallet(signer).connect_http(
        rpc_url.parse().expect("valid rpc url"),
    );

    // Build off-chain tree from historical Deposit events (on-chain source of truth).
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

    let recipient_balance_before = erc20_balance(&provider, token, recipient)
        .await
        .expect("recipient balance before");
    let owner_balance_before = erc20_balance(&provider, token, owner_addr)
        .await
        .expect("owner balance before");
    let pool_balance_before = erc20_balance(&provider, token, pool)
        .await
        .expect("pool balance before");

    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos() as u64;

    let nonce_m31 = |salt: u64| -> BaseField {
        let v = (((run_nonce ^ salt) % ((M31_MODULUS as u64) - 1)) + 1) as u32;
        BaseField::from_u32_unchecked(v)
    };

    let secret = nonce_m31(0x1234_0001);
    let nullifier = nonce_m31(0x5678_0002);
    let token_m31 = address_to_m31(token);

    let deposit_amount = BaseField::from_u32_unchecked(100);
    let withdraw_amount = BaseField::from_u32_unchecked(60);
    let refund_amount = BaseField::from_u32_unchecked(40);
    let commitment_amount = deposit_amount;

    let secret_nullifier_hash = poseidon_hash_pair(secret, nullifier);

    // 1) Approve
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

    // 2) Deposit
    let deposit_start_block = provider.get_block_number().await.expect("get block number before deposit");
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

    // Listen for deposit events after tx, then update off-chain tree from emitted commitment.
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
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(!new_logs.is_empty(), "expected Deposit event after deposit tx");

    new_logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });

    for log in new_logs {
        let commitment_topic = log
            .inner
            .topics()
            .get(1)
            .expect("deposit commitment topic");
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256)
            .expect("deposit commitment should fit M31/u32");
        offchain_tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }

    let onchain_root_u256 = current_root(&provider, pool).await.expect("on-chain root");
    let onchain_root_u32 = u32::try_from(onchain_root_u256).expect("on-chain root fits u32");
    assert_eq!(offchain_tree.root().0, onchain_root_u32, "off-chain root mismatch after processing Deposit event");

    // 3) Generate proof and send to external trusted server.
    let refund_secret = nonce_m31(0x9abc_0003);
    let refund_nullifier = nonce_m31(0xdef0_0004);
    let recipient_m31 = address_to_m31(recipient);

    let mut context = build_withdraw_merkle_context_from_offchain_tree(
        &offchain_tree,
        secret,
        nullifier,
        commitment_amount,
        token_m31,
        withdraw_amount,
        refund_secret,
        refund_nullifier,
        refund_amount,
        recipient_m31,
    )
    .expect("build withdraw context from offchain tree");

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
    let preprocessed_root: HashValue<QM31> = stark_proof.proof.commitments[0].into();
    println!("Preprocessed root withdraw circuit: {:?}", preprocessed_root);

    let sizes = TreeVec::concat_cols(proof.components.iter().map(|c| c.trace_log_degree_bounds()));

    let payload = VerifyAndSignRequest {
        proof_id: format!("e2e-deposit-withdraw-{}-{run_nonce}", deposit_start_block),
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
    let status = sign_resp.status();
    let body = sign_resp.text().await.expect("read trusted server response body");
    assert_eq!(status, reqwest::StatusCode::OK, "trusted server rejected proof: {body}");

    let parsed: VerifyAndSignResponse = serde_json::from_str(&body)
        .expect("decode trusted server response");
    assert!(parsed.verified, "trusted server did not verify proof");

    let root = U256::from(m31_from_claim_output(&payload.claim_output_values, 0) as u64);
    let nullifier = U256::from(m31_from_claim_output(&payload.claim_output_values, 1) as u64);
    let amount = U256::from(m31_from_claim_output(&payload.claim_output_values, 3) as u64);
    let refund_commitment_hash =
        U256::from(m31_from_claim_output(&payload.claim_output_values, 4) as u64);

    // 4) Submit withdraw on-chain with signed claim.
    send_tx(
        &provider,
        pool,
        IPrivacyPool::withdrawCall {
            root,
            nullifier,
            amount,
            refundCommitmentHash: refund_commitment_hash,
            signature: Bytes::from(
                hex::decode(parsed.signature_hex.trim_start_matches("0x"))
                    .expect("signature hex"),
            ),
            token,
            recipient,
        }
        .abi_encode()
        .into(),
        "withdraw",
    )
    .await
    .expect("withdraw tx should succeed");

    // Balance assertions.
    let recipient_balance_after = erc20_balance(&provider, token, recipient)
        .await
        .expect("recipient balance after");
    let owner_balance_after = erc20_balance(&provider, token, owner_addr)
        .await
        .expect("owner balance after");
    let pool_balance_after = erc20_balance(&provider, token, pool)
        .await
        .expect("pool balance after");

    assert_eq!(
        recipient_balance_after,
        recipient_balance_before + U256::from(withdraw_amount.0 as u64),
        "recipient should receive withdraw amount",
    );
    assert_eq!(
        owner_balance_before - owner_balance_after,
        U256::from(deposit_amount.0 as u64),
        "owner should spend exactly deposited amount",
    );
    assert_eq!(
        pool_balance_after,
        pool_balance_before + U256::from(refund_amount.0 as u64),
        "pool should keep refund remainder after withdraw",
    );
}
