use circuits::blake::HashValue;
use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use base64::Engine;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment};
use circuits::context::Context;
use stwo::core::{fields::{m31::BaseField, qm31::QM31}, pcs::TreeVec};
use stwo_circuit::{
    offchain_merkle::{OffchainMerkleTree, poseidon_hash_pair},
    paymoney_circuits::{
        recursive_create_offer_circuit::{
            build_null_offer_context, build_recursive_offer_context, build_offer_terminal_context,
            TERMINAL_IDX_OFFER_COMMITMENT, TERMINAL_IDX_OFFER_REFUND_SN_HASH,
        },
        withdraw_circuit::build_withdraw_merkle_context_from_offchain_tree,
    },
};
use trusted_stwo_server::types::{
    VerifyAndSignRecursiveCreateOfferRequest, VerifyAndSignRecursiveCreateOfferResponse,
};

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    interface IPrivacyPool {
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function recursiveCreateOffer(
            bytes32 proofHash,
            uint32[] calldata batchNullifiers,
            uint32[] calldata batchRoots,
            uint256 totalAmount,
            address token,
            uint32 offerCommitment,
            uint32 offerRefundSnHash,
            uint32 secretHash,
            bytes calldata signature
        ) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
        function isValidRoot(uint256 root) external view returns (bool);
        function isNullifierUsed(uint256 nullifier) external view returns (bool);
        function getOffersTreeRoot() external view returns (uint256);
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

fn m31(v: BaseField) -> QM31 {
    QM31::from(v.0)
}

fn bf(v: u32) -> BaseField {
    BaseField::from_u32_unchecked(v)
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

async fn current_root(provider: &impl Provider, pool: Address) -> Result<U256, String> {
    let calldata = IPrivacyPool::getCurrentRootCall {}.abi_encode();
    let raw = provider
        .call(TransactionRequest::default().to(pool).input(calldata.into()))
        .await
        .map_err(|e| format!("getCurrentRoot failed: {e}"))?;
    IPrivacyPool::getCurrentRootCall::abi_decode_returns(&raw)
        .map_err(|e| format!("getCurrentRoot decode failed: {e}"))
}

async fn is_nullifier_used(provider: &impl Provider, pool: Address, nullifier: U256) -> Result<bool, String> {
    let calldata = IPrivacyPool::isNullifierUsedCall { nullifier }.abi_encode();
    let raw = provider
        .call(TransactionRequest::default().to(pool).input(calldata.into()))
        .await
        .map_err(|e| format!("isNullifierUsed failed: {e}"))?;
    IPrivacyPool::isNullifierUsedCall::abi_decode_returns(&raw)
        .map_err(|e| format!("isNullifierUsed decode failed: {e}"))
}

async fn offers_tree_root(provider: &impl Provider, pool: Address) -> Result<U256, String> {
    let calldata = IPrivacyPool::getOffersTreeRootCall {}.abi_encode();
    let raw = provider
        .call(TransactionRequest::default().to(pool).input(calldata.into()))
        .await
        .map_err(|e| format!("getOffersTreeRoot failed: {e}"))?;
    IPrivacyPool::getOffersTreeRootCall::abi_decode_returns(&raw)
        .map_err(|e| format!("getOffersTreeRoot decode failed: {e}"))
}

struct ProofBundle {
    preprocessed: PreprocessedCircuit,
    proof: CircuitProof,
}

impl std::fmt::Debug for ProofBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofBundle").finish()
    }
}

fn make_bundle(mut context: Context<QM31>) -> ProofBundle {
    context.finalize_guessed_vars();
    context.validate_circuit();
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    let proof = prove_circuit_assignment(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    assert!(proof.stark_proof.is_ok(), "proof generation failed");
    ProofBundle { preprocessed, proof }
}

fn log_root(label: &str, proof: &CircuitProof) {
    let hash: HashValue<QM31> = proof
        .stark_proof.as_ref().expect("stark proof")
        .proof.commitments[0].into();
    let a = hash.0.to_m31_array();
    let b = hash.1.to_m31_array();
    println!(
        "[root] {label}: [{}, {}, {}, {}, {}, {}, {}, {}]",
        a[0].0, a[1].0, a[2].0, a[3].0, b[0].0, b[1].0, b[2].0, b[3].0
    );
}

fn claim_output_u32(proof: &CircuitProof, idx: usize) -> u32 {
    let limbs = proof.claim.output_values[idx].to_m31_array();
    assert_eq!(limbs[1].0, 0, "claim output[{idx}] must be scalar QM31");
    assert_eq!(limbs[2].0, 0);
    assert_eq!(limbs[3].0, 0);
    limbs[0].0
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_recursive_create_offer() {
    let pool: Address = PRIVACY_POOL_ADDRESS.parse().expect("valid pool address");
    let token: Address = TOKEN_ADDRESS.parse().expect("valid token address");

    let signer: PrivateKeySigner = OWNER_PRIVATE_KEY.parse().expect("valid private key");
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(RPC_URL.parse().expect("valid rpc url"));

    let amounts: [u32; 4] = [100, 200, 150, 50];
    let total_amount: u32 = amounts.iter().sum(); // 500

    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos() as u64;

    let nonce_m31 = |salt: u64| -> BaseField {
        let v = (((run_nonce ^ salt) % ((M31_MODULUS as u64) - 1)) + 1) as u32;
        BaseField::from_u32_unchecked(v)
    };

    let secrets: [BaseField; 4] = std::array::from_fn(|i| nonce_m31(0x1000_0000 + i as u64));
    let raw_nullifiers: [BaseField; 4] = std::array::from_fn(|i| nonce_m31(0x2000_0000 + i as u64));
    let refund_secrets: [BaseField; 4] = std::array::from_fn(|i| nonce_m31(0x3000_0000 + i as u64));
    let refund_nullifiers: [BaseField; 4] = std::array::from_fn(|i| nonce_m31(0x4000_0000 + i as u64));
    let token_m31 = address_to_m31(token);

    // Offer-specific private data — stays local, proven inside the terminal circuit.
    let offer_secret = nonce_m31(0x5000_0000);
    let offer_nullifier = nonce_m31(0x6000_0000);
    let offer_refund_secret = nonce_m31(0x7000_0000);
    let offer_refund_nullifier = nonce_m31(0x8000_0000);
    let secret_hash = poseidon_hash_pair(offer_secret, offer_secret);
    let fiat_amount = bf(50_000);
    let currency_hash = bf(12345);
    let rev_tag_hash = bf(67890);

    // ── Build off-chain tree from historical Deposit events ───────────────────
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
        let commitment_topic = log.inner.topics().get(1).expect("deposit commitment topic");
        let commitment_u32 = u32::try_from(U256::from_be_slice(commitment_topic.as_slice()))
            .expect("commitment fits u32");
        offchain_tree.add_leaf(bf(commitment_u32));
    }

    // ── Approve and make 4 deposits ───────────────────────────────────────────
    send_tx(
        &provider,
        token,
        IERC20::approveCall { spender: pool, amount: U256::from(total_amount as u64) }
            .abi_encode().into(),
        "approve",
    ).await.expect("approve tx");

    let deposit_start_block = provider.get_block_number().await.expect("get block number");

    for i in 0..4 {
        let sn_hash = poseidon_hash_pair(secrets[i], raw_nullifiers[i]);
        send_tx(
            &provider,
            pool,
            IPrivacyPool::depositCall {
                secretNullifierHash: U256::from(sn_hash.0 as u64),
                amount: U256::from(amounts[i] as u64),
                token,
            }.abi_encode().into(),
            &format!("deposit[{i}]"),
        ).await.expect("deposit tx");
    }

    // ── Sync off-chain tree with on-chain deposits ────────────────────────────
    let mut new_logs = Vec::new();
    for _ in 0..30 {
        let logs = provider
            .get_logs(
                &Filter::new()
                    .address(pool)
                    .from_block(deposit_start_block)
                    .event("Deposit(uint256,uint256,address,uint64,uint256)"),
            )
            .await
            .expect("fetch deposit logs");
        if logs.len() >= 4 {
            new_logs = logs;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(new_logs.len(), 4, "expected 4 Deposit events");

    new_logs.sort_by_key(|log| {
        (log.block_number.unwrap_or_default(), log.log_index.unwrap_or_default())
    });
    for log in &new_logs {
        let commitment_topic = log.inner.topics().get(1).expect("deposit commitment topic");
        let commitment_u32 = u32::try_from(U256::from_be_slice(commitment_topic.as_slice()))
            .expect("commitment fits u32");
        offchain_tree.add_leaf(bf(commitment_u32));
    }

    let onchain_root = current_root(&provider, pool).await.expect("on-chain root");
    let onchain_root_u32 = u32::try_from(onchain_root).expect("root fits u32");
    assert_eq!(
        offchain_tree.root().0, onchain_root_u32,
        "off-chain root must match on-chain root after all deposits"
    );

    // ── Prove 4 withdrawals (full amount, no refund) ──────────────────────────
    // Recipient is irrelevant for offer accumulation — we use a dummy value.
    let dummy_recipient = bf(1);
    let withdraw_bundles: Vec<ProofBundle> = (0..4)
        .map(|i| {
            let ctx = build_withdraw_merkle_context_from_offchain_tree(
                &offchain_tree,
                secrets[i],
                raw_nullifiers[i],
                bf(amounts[i]),
                token_m31,
                bf(amounts[i]),
                refund_secrets[i],
                refund_nullifiers[i],
                bf(0),
                dummy_recipient,
            )
            .expect("build withdraw context");
            make_bundle(ctx)
        })
        .collect();

    let batch_nullifiers: Vec<u32> = withdraw_bundles.iter()
        .map(|b| claim_output_u32(&b.proof, 1))
        .collect();
    let batch_roots: Vec<u32> = withdraw_bundles.iter()
        .map(|b| claim_output_u32(&b.proof, 0))
        .collect();

    // ── Build recursive offer accumulation chain ──────────────────────────────
    let [w0, w1, w2, w3]: [ProofBundle; 4] = withdraw_bundles
        .try_into().expect("4 withdraw bundles");

    let null_bundle = make_bundle(build_null_offer_context(m31(token_m31)));
    log_root("null offer circuit", &null_bundle.proof);
    log_root("withdraw circuit (depth-31)", &w0.proof);

    let rec_0 = make_bundle(build_recursive_offer_context(
        &null_bundle.preprocessed, null_bundle.proof,
        &w0.preprocessed, w0.proof,
    ));
    log_root("RECURSIVE_OFFER_STEP1 (null+w0)", &rec_0.proof);

    let rec_1 = make_bundle(build_recursive_offer_context(
        &rec_0.preprocessed, rec_0.proof,
        &w1.preprocessed, w1.proof,
    ));
    log_root("RECURSIVE_OFFER_STEP2 (rec+w1)", &rec_1.proof);

    let rec_2 = make_bundle(build_recursive_offer_context(
        &rec_1.preprocessed, rec_1.proof,
        &w2.preprocessed, w2.proof,
    ));
    log_root("RECURSIVE_OFFER_STEP3 (rec+w2)", &rec_2.proof);

    let final_bundle = make_bundle(build_recursive_offer_context(
        &rec_2.preprocessed, rec_2.proof,
        &w3.preprocessed, w3.proof,
    ));
    log_root("RECURSIVE_OFFER_STEP4/STABLE (rec+w3)", &final_bundle.proof);

    assert_eq!(
        claim_output_u32(&final_bundle.proof, 3),
        total_amount,
        "accumulated proof must aggregate total amount"
    );

    // ── Terminal circuit: proves offerCommitment in ZK ────────────────────────
    let terminal_bundle = make_bundle(build_offer_terminal_context(
        &final_bundle.preprocessed,
        final_bundle.proof,
        m31(offer_secret),
        m31(offer_nullifier),
        m31(fiat_amount),
        m31(currency_hash),
        m31(rev_tag_hash),
        m31(offer_refund_secret),
        m31(offer_refund_nullifier),
    ));
    log_root("OFFER_TERMINAL", &terminal_bundle.proof);

    assert_eq!(
        claim_output_u32(&terminal_bundle.proof, 3),
        total_amount,
        "terminal proof must preserve total amount"
    );
    assert_eq!(
        claim_output_u32(&terminal_bundle.proof, 2),
        token_m31.0,
        "terminal proof must preserve token"
    );

    // ── Serialize terminal proof and send to trusted server ───────────────────
    let terminal_stark = terminal_bundle.proof.stark_proof.as_ref().expect("stark proof");
    let stark_proof_bytes = bincode::serialize(terminal_stark).expect("serialize stark proof");
    let sizes = TreeVec::concat_cols(
        terminal_bundle.proof.components.iter().map(|c| c.trace_log_degree_bounds())
    );

    let request = VerifyAndSignRecursiveCreateOfferRequest {
        proof_id: format!("e2e-recursive-create-offer-{run_nonce}"),
        pcs_config_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&terminal_bundle.proof.pcs_config).expect("serialize pcs_config")),
        stark_proof_b64: base64::engine::general_purpose::STANDARD.encode(&stark_proof_bytes),
        channel_salt: terminal_bundle.proof.channel_salt,
        interaction_pow_nonce: terminal_bundle.proof.interaction_pow_nonce,
        claim_log_sizes: terminal_bundle.proof.claim.log_sizes.to_vec(),
        claim_output_values: terminal_bundle.proof.claim.output_values.iter()
            .copied().map(qm31_to_u32s).collect(),
        interaction_claimed_sums: terminal_bundle.proof.interaction_claim.claimed_sums.iter()
            .copied().map(qm31_to_u32s).collect(),
        stage1_trace_log_sizes: sizes[1].clone(),
        stage2_trace_log_sizes: sizes[2].clone(),
        preprocessed_trace_log_sizes: terminal_bundle.preprocessed.preprocessed_trace.log_sizes(),
        preprocessed_column_ids: terminal_bundle.preprocessed.preprocessed_trace.ids()
            .iter().map(|id| id.id.clone()).collect(),
        output_addresses: terminal_bundle.preprocessed.params.output_addresses.clone(),
        n_blake_gates: terminal_bundle.preprocessed.params.n_blake_gates,
        nullifiers: batch_nullifiers.clone(),
        merkle_roots: batch_roots.clone(),
        secret_hash: secret_hash.0,
    };

    let trusted_server_url = std::env::var("TRUSTED_SERVER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    let resp = reqwest::Client::new()
        .post(format!("{trusted_server_url}/verify-and-sign-recursive-create-offer"))
        .json(&request)
        .send()
        .await
        .expect("trusted server request failed");
    let status = resp.status();
    let body = resp.text().await.expect("read response body");
    assert_eq!(status, reqwest::StatusCode::OK, "trusted server rejected proof: {body}");

    let parsed: VerifyAndSignRecursiveCreateOfferResponse =
        serde_json::from_str(&body).expect("decode trusted server response");
    assert!(parsed.verified, "trusted server did not verify proof");
    assert_eq!(parsed.total_amount, total_amount, "server response amount mismatch");
    assert_eq!(parsed.nullifiers, batch_nullifiers, "server echoed wrong nullifiers");
    assert_eq!(parsed.merkle_roots, batch_roots, "server echoed wrong roots");
    assert_eq!(parsed.secret_hash, secret_hash.0, "server echoed wrong secret_hash");

    // offerCommitment and offerRefundSnHash come from ZK circuit outputs — not server-computed.
    let circuit_offer_commitment = claim_output_u32(&terminal_bundle.proof, TERMINAL_IDX_OFFER_COMMITMENT);
    let circuit_offer_refund_sn_hash = claim_output_u32(&terminal_bundle.proof, TERMINAL_IDX_OFFER_REFUND_SN_HASH);
    assert_eq!(parsed.offer_commitment, circuit_offer_commitment, "server must echo circuit output[4]");
    assert_eq!(parsed.offer_refund_sn_hash, circuit_offer_refund_sn_hash, "server must echo circuit output[6]");

    println!("offer_commitment (ZK-proven): {}", parsed.offer_commitment);
    println!("secret_hash: {}", parsed.secret_hash);

    let proof_hash_bytes = hex::decode(parsed.proof_hash_hex.trim_start_matches("0x"))
        .expect("decode proof_hash_hex");
    let proof_hash: FixedBytes<32> = FixedBytes::from_slice(&proof_hash_bytes);

    let signature_bytes = hex::decode(parsed.signature_hex.trim_start_matches("0x"))
        .expect("decode signature_hex");

    let offers_tree_root_before = offers_tree_root(&provider, pool)
        .await.expect("offers tree root before");

    // ── Submit recursiveCreateOffer on-chain ──────────────────────────────────
    send_tx(
        &provider,
        pool,
        IPrivacyPool::recursiveCreateOfferCall {
            proofHash: proof_hash,
            batchNullifiers: batch_nullifiers.clone(),
            batchRoots: batch_roots.clone(),
            totalAmount: U256::from(total_amount as u64),
            token,
            offerCommitment: parsed.offer_commitment,
            offerRefundSnHash: parsed.offer_refund_sn_hash,
            secretHash: parsed.secret_hash,
            signature: Bytes::from(signature_bytes),
        }.abi_encode().into(),
        "recursiveCreateOffer",
    ).await.expect("recursiveCreateOffer tx should succeed");

    // ── Assertions ────────────────────────────────────────────────────────────
    let offers_tree_root_after = offers_tree_root(&provider, pool)
        .await.expect("offers tree root after");

    assert_ne!(
        offers_tree_root_after, offers_tree_root_before,
        "offersTree root must change after recursiveCreateOffer"
    );

    for &n in &batch_nullifiers {
        assert!(
            is_nullifier_used(&provider, pool, U256::from(n as u64))
                .await.expect("isNullifierUsed call"),
            "nullifier {n} must be marked as used after recursiveCreateOffer"
        );
    }
}
