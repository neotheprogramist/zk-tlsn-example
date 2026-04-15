use alloy::{
    primitives::{Address, Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionReceipt, TransactionRequest},
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
    withdraw::offer_circuit::build_offer_merkle_context_from_offchain_tree,
    withdraw::offer_spend_cancel_circuit::build_offer_spend_cancel_context_from_offchain_tree,
};
use trusted_stwo_server::Signer;
use trusted_stwo_server::types::{
    VerifyAndSignRequest, VerifyAndSignResponse,
    VerifyTlsnAndSignTransactionSettlementRequest, VerifyTlsnAndSignTransactionSettlementResponse,
};
use tlsnotary::{
    BodyFieldConfig, CertificateDer, MpcTlsConfig, Prover, RootCertStore,
    ServerName, TlsClientConfig, TlsCommitConfig, Verifier, VerifierConfig,
    prover::RevealConfig,
};

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
        function createTransaction(uint256 offerSecretHash, uint256 cryptoAmount, string calldata title) external returns (bytes32);
        function verifyTransaction(
            bytes32 transactionId,
            uint256 fiatAmount,
            uint256 cryptoAmount,
            uint256 secretNullifierHash,
            bytes calldata settlementSignature,
            uint32[4][] calldata offerCircuitOutputs,
            bytes calldata offerCircuitSignature
        ) external;
        function getOffersTreeRoot() external view returns (uint256);
        function isOfferNullifierUsed(uint256 nullifier) external view returns (bool);
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
        function getIndexedNullifierRoot() external view returns (uint256);
        function offers(uint256 secretHash) external view returns (
            address tokenAddress,
            uint8 status,
            uint256 cryptoAmount,
            uint256 timestamp,
            uint256 offerRefundSecretNullifierHash
        );
    }
}

const RPC_URL: &str = "http://127.0.0.1:8545";
const PRIVACY_POOL_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TOKEN_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const OWNER_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TAKER_PRIVATE_KEY: &str =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
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

fn u32be(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

fn m31_u32(value: U256, label: &str) -> u32 {
    let v = u32::try_from(value).unwrap_or_else(|_| panic!("{label} does not fit u32"));
    assert!(v < M31_MODULUS, "{label} is not valid M31");
    v
}

fn withdraw_claim_hash(
    root: u32,
    nullifier: u32,
    token_m31: u32,
    amount: u32,
    refund_commitment_hash: u32,
    recipient_m31: u32,
) -> [u8; 32] {
    let mut claim = Vec::with_capacity(24 + 6 * 4);
    claim.extend_from_slice(b"trusted-stwo-claim-v1");
    claim.extend_from_slice(&u32be(root));
    claim.extend_from_slice(&u32be(nullifier));
    claim.extend_from_slice(&u32be(token_m31));
    claim.extend_from_slice(&u32be(amount));
    claim.extend_from_slice(&u32be(refund_commitment_hash));
    claim.extend_from_slice(&u32be(recipient_m31));
    keccak256(claim).0
}

fn withdraw_message_hash(claim_hash: [u8; 32]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(24 + 32);
    msg.extend_from_slice(b"trusted-stwo-message-v1");
    msg.extend_from_slice(&claim_hash);
    keccak256(msg).0
}

async fn send_tx_with_receipt(
    provider: &impl Provider,
    to: Address,
    input: Bytes,
    label: &str,
) -> Result<TransactionReceipt, String> {
    let tx = TransactionRequest::default().to(to).input(input.into());
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| format!("{label} send failed: {e}"))?;
    let tx_hash = *pending.tx_hash();
    // Cap receipt polling at 30 s — a stuck tx should not hang the whole test suite.
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
    Ok(receipt)
}

async fn send_tx(provider: &impl Provider, to: Address, input: Bytes, label: &str) {
    send_tx_with_receipt(provider, to, input, label)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
}

async fn build_offchain_offers_tree_from_chain(
    provider: &impl Provider,
    pool: Address,
) -> OffchainMerkleTree {
    let mut tree = OffchainMerkleTree::new(31);
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .from_block(0u64)
                .event("OfferCreated(uint256,uint256,address,uint256)"),
        )
        .await
        .expect("fetch OfferCreated logs");

    for log in logs {
        // OfferCreated: indexed [0]=offerCommitment, [1]=secretHash, [2]=tokenAddress, data=cryptoAmount
        let commitment_topic = log.inner.topics().get(1).expect("OfferCreated commitment topic");
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256).expect("offerCommitment fits u32");
        tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }
    tree
}

async fn build_offchain_tree_from_chain(provider: &impl Provider, pool: Address) -> OffchainMerkleTree {
    let mut tree = OffchainMerkleTree::new(31);
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .from_block(0u64)
                .event("Deposit(uint256,uint256,address,uint64,uint256)"),
        )
        .await
        .expect("fetch deposit logs");

    for log in logs {
        let commitment_topic = log.inner.topics().get(1).expect("deposit commitment topic");
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256).expect("commitment fits u32");
        tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }
    tree
}

/// Run a real TLSN session against the in-process mock bank server.
/// The prover makes an MPC-TLS connection through the verifier to `GET /api/transfer/{tx_title}`.
/// Returns a reconstructed clean HTTP response string built from the revealed TLSN fields.
fn run_tlsn_transfer_session(tx_title: &str, rev_tag: &str, fiat_amount: u64) -> String {
    // Configure the mock bank before it starts reading env vars in AppState::new().
    // Safety: single-threaded at this point (called from spawn_blocking, test is sequential).
    unsafe {
        std::env::set_var("MOCK_REV_TAG", rev_tag);
        std::env::set_var("MOCK_FIAT_AMOUNT", fiat_amount.to_string());
    }

    let tx_title = tx_title.to_string();

    smol::block_on(async move {
        let tls = shared::create_test_tls_config().expect("TLS config");

        let (prover_server, server_sock) = smol::net::unix::UnixStream::pair().expect("server socket pair");
        let (prover_verifier, verifier_sock) = smol::net::unix::UnixStream::pair().expect("verifier socket pair");

        let app = server::app::get_app(std::collections::HashMap::new());
        let server_task = server::handle_connection(app, tls.server_config, server_sock);

        let server_name = ServerName::Dns(
            "localhost".to_string().try_into().expect("DNS name"),
        );
        let tls_client_config = TlsClientConfig::builder()
            .server_name(server_name)
            .root_store(RootCertStore { roots: vec![CertificateDer(tls.cert_bytes.clone())] })
            .build()
            .expect("TLS client config");
        let tls_commit_config = TlsCommitConfig::builder()
            .protocol(
                MpcTlsConfig::builder()
                    .max_sent_data(1 << 12)
                    .max_recv_data(1 << 14)
                    .build()
                    .expect("MPC-TLS config"),
            )
            .build()
            .expect("TLS commit config");

        let request = hyper::Request::builder()
            .method("GET")
            .uri(format!("/api/transfer/{tx_title}"))
            .header("content-type", "application/json")
            .header("Connection", "close")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .expect("HTTP request");

        let prover = Prover::builder()
            .tls_client_config(tls_client_config)
            .tls_commit_config(tls_commit_config)
            .request(request)
            .request_reveal_config(RevealConfig {
                reveal_headers: vec!["content-type".into()],
                commit_headers: vec!["connection".into()],
                reveal_body_fields: vec![],
                commit_body_fields: vec![],
                reveal_keys_commit_values: vec![],
            })
            .response_reveal_config(RevealConfig {
                reveal_headers: vec!["x-revolut-signature".into()],
                commit_headers: vec![],
                // All three body fields are revealed so the trusted server can read them.
                // fiatAmount is revealed (not committed) because the trusted server must
                // include it in the signed settlement claim.
                reveal_body_fields: vec![
                    BodyFieldConfig::Quoted(".commentData".into()),
                    BodyFieldConfig::Quoted(".revTag".into()),
                    BodyFieldConfig::Unquoted(".fiatAmount".into()),
                ],
                commit_body_fields: vec![],
                reveal_keys_commit_values: vec![],
            })
            .build()
            .expect("TLSN prover");

        let verifier = Verifier::builder()
            .verifier_config(
                VerifierConfig::builder()
                    .root_store(RootCertStore { roots: vec![CertificateDer(tls.cert_bytes)] })
                    .build()
                    .expect("verifier config"),
            )
            .build()
            .expect("TLSN verifier");

        let (server_result, _prover_result, verifier_result) = futures::join!(
            server_task,
            prover.prove(prover_verifier, prover_server),
            verifier.verify(verifier_sock),
        );

        server_result.expect("mock bank server completed");
        let verifier_output = verifier_result.expect("TLSN verifier completed");

        // received_unsafe() contains the raw TLS application bytes with null bytes (\0) where
        // non-revealed (committed) data was. Reconstruct a clean HTTP response from revealed fields.
        let raw = verifier_output.transcript.received_unsafe();
        reconstruct_http_from_tlsn_partial(raw)
            .expect("reconstruct HTTP response from TLSN partial transcript")
    })
}

/// Extract revealed fields from a TLSN partial transcript (null bytes at non-revealed positions)
/// and reconstruct a clean HTTP/1.1 response string the trusted server can parse.
fn reconstruct_http_from_tlsn_partial(raw: &[u8]) -> Result<String, String> {
    let sig_value = extract_header_value(raw, b"x-revolut-signature: ")
        .ok_or("missing x-revolut-signature in TLSN transcript")?;
    let comment_data = extract_quoted_json_value(raw, b"\"commentData\":\"")
        .ok_or("missing commentData in TLSN transcript")?;
    let rev_tag = extract_quoted_json_value(raw, b"\"revTag\":\"")
        .ok_or("missing revTag in TLSN transcript")?;
    let fiat_amount = extract_unquoted_json_number(raw, b"\"fiatAmount\":")
        .ok_or("missing/zeroed fiatAmount in TLSN transcript")?;

    Ok(format!(
        "HTTP/1.1 200 OK\r\nx-revolut-signature: {sig_value}\r\n\r\n{{\"commentData\":\"{comment_data}\",\"revTag\":\"{rev_tag}\",\"fiatAmount\":{fiat_amount}}}"
    ))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract a header value: bytes after `prefix` until `\r` or `\0`.
fn extract_header_value(raw: &[u8], prefix: &[u8]) -> Option<String> {
    let start = find_subsequence(raw, prefix)? + prefix.len();
    let end = raw[start..]
        .iter()
        .position(|&b| b == b'\r' || b == 0)
        .map(|i| start + i)?;
    std::str::from_utf8(&raw[start..end]).ok().map(str::to_string)
}

/// Extract a quoted JSON string value: bytes after `key_prefix` (which ends with `:"`) until `"`.
fn extract_quoted_json_value(raw: &[u8], key_prefix: &[u8]) -> Option<String> {
    let start = find_subsequence(raw, key_prefix)? + key_prefix.len();
    let end = raw[start..]
        .iter()
        .position(|&b| b == b'"')?
        + start;
    std::str::from_utf8(&raw[start..end]).ok().map(str::to_string)
}

/// Extract an unquoted JSON number value: ASCII digits after `key_prefix` (which ends with `:`).
fn extract_unquoted_json_number(raw: &[u8], key_prefix: &[u8]) -> Option<String> {
    let start = find_subsequence(raw, key_prefix)? + key_prefix.len();
    let end = raw[start..]
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .map(|i| start + i)
        .unwrap_or(raw.len());
    if start == end {
        return None; // value is zeroed / not revealed
    }
    std::str::from_utf8(&raw[start..end]).ok().map(str::to_string)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_offer_transaction_verify_and_withdraw() {
    let pool: Address = PRIVACY_POOL_ADDRESS.parse().expect("pool address");
    let token: Address = TOKEN_ADDRESS.parse().expect("token address");

    let owner_signer: PrivateKeySigner = OWNER_PRIVATE_KEY.parse().expect("owner key");
    let taker_signer: PrivateKeySigner = TAKER_PRIVATE_KEY.parse().expect("taker key");
    let owner = owner_signer.address();
    let taker = taker_signer.address();

    let provider_owner = ProviderBuilder::new().wallet(owner_signer).connect_http(
        RPC_URL.parse().expect("rpc url"),
    );
    let provider_taker = ProviderBuilder::new().wallet(taker_signer).connect_http(
        RPC_URL.parse().expect("rpc url"),
    );

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

    // owner creates deposit and offer
    let owner_secret = nonce_m31(0x1000_0001);
    let owner_nullifier: circuit_air::components::prelude::M31 = nonce_m31(0x1000_0002);
    let owner_amount = BaseField::from_u32_unchecked(100);
    let owner_secret_nullifier_hash = poseidon_hash_pair(owner_secret, owner_nullifier);

    send_tx(
        &provider_owner,
        token,
        IERC20::approveCall {
            spender: pool,
            amount: U256::from(owner_amount.0 as u64),
        }
        .abi_encode()
        .into(),
        "owner approve",
    )
    .await;

    send_tx(
        &provider_owner,
        pool,
        IPrivacyPool::depositCall {
            secretNullifierHash: U256::from(owner_secret_nullifier_hash.0 as u64),
            amount: U256::from(owner_amount.0 as u64),
            token,
        }
        .abi_encode()
        .into(),
        "owner deposit",
    )
    .await;

    let offchain_tree = build_offchain_tree_from_chain(&provider_owner, pool).await;

    let token_m31 = address_to_m31(token);
    let offer_amount = BaseField::from_u32_unchecked(30);
    let offer_refund_amount = BaseField::from_u32_unchecked(70);
    let offer_secret = nonce_m31(0x1000_0011);
    let offer_nullifier = nonce_m31(0x1000_0012);
    let offer_fiat = BaseField::from_u32_unchecked(123);
    let offer_currency_str = "PLN";
    let offer_rev_str = "@testrevtag";
    let offer_currency = str_to_m31(offer_currency_str);
    let offer_rev = str_to_m31(offer_rev_str);
    let offer_refund_secret = nonce_m31(0x1000_0021);
    let offer_refund_nullifier = nonce_m31(0x1000_0022);
    // post-use seller refund key — embedded in offerCommitment; seller uses it to claim remaining
    let post_use_refund_secret = nonce_m31(0x1000_0031);
    let post_use_refund_nullifier = nonce_m31(0x1000_0032);

    let mut offer_ctx = build_offer_merkle_context_from_offchain_tree(
        &offchain_tree,
        owner_secret,
        owner_nullifier,
        owner_amount,
        token_m31,
        offer_amount,
        offer_secret,
        offer_nullifier,
        offer_fiat,
        offer_currency,
        offer_rev,
        post_use_refund_secret,
        post_use_refund_nullifier,
        offer_refund_secret,
        offer_refund_nullifier,
        offer_refund_amount,
    )
    .expect("offer context from offchain tree");
    offer_ctx.finalize_guessed_vars();
    offer_ctx.validate_circuit();

    let offer_preprocessed = PreprocessedCircuit::preprocess_circuit(&mut offer_ctx);
    let offer_proof = prove_circuit_assignment(
        offer_ctx.values(),
        &offer_preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    let stark_offer = offer_proof.stark_proof.expect("offer stark proof");

    let offer_sizes =
        TreeVec::concat_cols(offer_proof.components.iter().map(|c| c.trace_log_degree_bounds()));

    let offer_payload = VerifyAndSignRequest {
        proof_id: format!("e2e-offer-transaction-offer-{run_nonce}"),
        pcs_config_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&offer_proof.pcs_config).expect("serialize pcs")),
        stark_proof_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&stark_offer).expect("serialize proof")),
        channel_salt: offer_proof.channel_salt,
        interaction_pow_nonce: offer_proof.interaction_pow_nonce,
        claim_log_sizes: offer_proof.claim.log_sizes.to_vec(),
        claim_output_values: offer_proof
            .claim
            .output_values
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        interaction_claimed_sums: offer_proof
            .interaction_claim
            .claimed_sums
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        stage1_trace_log_sizes: offer_sizes[1].clone(),
        stage2_trace_log_sizes: offer_sizes[2].clone(),
        preprocessed_trace_log_sizes: offer_preprocessed.preprocessed_trace.log_sizes(),
        preprocessed_column_ids: offer_preprocessed
            .preprocessed_trace
            .ids()
            .iter()
            .map(|id| id.id.clone())
            .collect(),
        output_addresses: offer_preprocessed.params.output_addresses.clone(),
        n_blake_gates: offer_preprocessed.params.n_blake_gates,
    };

    let trusted_server_url =
        std::env::var("TRUSTED_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    let offer_sign_resp = reqwest::Client::new()
        .post(format!("{trusted_server_url}/verify-and-sign"))
        .json(&offer_payload)
        .send()
        .await
        .expect("offer sign request");
    let offer_sign_status = offer_sign_resp.status();
    let offer_sign_body = offer_sign_resp
        .text()
        .await
        .expect("offer sign response body");
    assert!(
        offer_sign_status.is_success(),
        "offer sign failed: status={}, body={}",
        offer_sign_status,
        offer_sign_body
    );
    let offer_sign: VerifyAndSignResponse =
        serde_json::from_str(&offer_sign_body).expect("offer sign response json");

    let offer_secret_hash = poseidon_hash_pair(offer_secret, offer_secret);

    println!("Create Offer tx");
    send_tx(
        &provider_owner,
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
    .await;
    println!("After create offer tx");

    // ── Seller generates offer_spend_cancel proof (offersTree membership + spend nullifier) ──────
    // Only the seller knows offer_secret / offer_nullifier / offer_refund params.
    // The seller produces this proof once; the buyer submits it together with the TLSN claim.
    let offers_tree = build_offchain_offers_tree_from_chain(&provider_owner, pool).await;


    let offer_nullifier_hash_val = poseidon_hash_pair(offer_secret, offer_secret);
    println!(
        "offer_nullifier_hash (spend) = {}",
        poseidon_hash_pair(offer_secret, offer_nullifier).0
    );
    println!("offersTree root = {}", offers_tree.root().0);

    let mut spend_ctx = build_offer_spend_cancel_context_from_offchain_tree(
        &offers_tree,
        offer_secret,
        offer_nullifier,
        offer_amount,
        token_m31,
        offer_fiat,
        offer_currency,
        offer_rev,
        post_use_refund_secret,
        post_use_refund_nullifier,
    )
    .expect("offer_spend_cancel context from offchain offers tree");
    spend_ctx.finalize_guessed_vars();
    spend_ctx.validate_circuit();

    let spend_preprocessed = PreprocessedCircuit::preprocess_circuit(&mut spend_ctx);
    let spend_proof = prove_circuit_assignment(
        spend_ctx.values(),
        &spend_preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    let stark_spend = spend_proof.stark_proof.expect("spend stark proof");

    let spend_sizes =
        TreeVec::concat_cols(spend_proof.components.iter().map(|c| c.trace_log_degree_bounds()));

    let spend_payload = VerifyAndSignRequest {
        proof_id: format!("e2e-offer-spend-{run_nonce}"),
        pcs_config_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&spend_proof.pcs_config).expect("serialize pcs")),
        stark_proof_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&stark_spend).expect("serialize spend proof")),
        channel_salt: spend_proof.channel_salt,
        interaction_pow_nonce: spend_proof.interaction_pow_nonce,
        claim_log_sizes: spend_proof.claim.log_sizes.to_vec(),
        claim_output_values: spend_proof
            .claim
            .output_values
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        interaction_claimed_sums: spend_proof
            .interaction_claim
            .claimed_sums
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        stage1_trace_log_sizes: spend_sizes[1].clone(),
        stage2_trace_log_sizes: spend_sizes[2].clone(),
        preprocessed_trace_log_sizes: spend_preprocessed.preprocessed_trace.log_sizes(),
        preprocessed_column_ids: spend_preprocessed
            .preprocessed_trace
            .ids()
            .iter()
            .map(|id| id.id.clone())
            .collect(),
        output_addresses: spend_preprocessed.params.output_addresses.clone(),
        n_blake_gates: spend_preprocessed.params.n_blake_gates,
    };

    let spend_sign_resp = reqwest::Client::new()
        .post(format!("{trusted_server_url}/verify-and-sign"))
        .json(&spend_payload)
        .send()
        .await
        .expect("spend sign request");
    let spend_sign_status = spend_sign_resp.status();
    let spend_sign_body = spend_sign_resp
        .text()
        .await
        .expect("spend sign response body");
    assert!(
        spend_sign_status.is_success(),
        "spend sign failed: status={}, body={}",
        spend_sign_status,
        spend_sign_body
    );
    let spend_sign: VerifyAndSignResponse =
        serde_json::from_str(&spend_sign_body).expect("spend sign response json");
    let _ = offer_nullifier_hash_val; // suppress unused warning

    // Taker does NOT need an on-chain deposit in this flow.
    // Fiat payment is done off-chain and reflected in signed settlement payload.

    // Buy only 20 of 30 so that remaining=10 exercises the seller use-once refund path.
    let crypto_amount_u64 = 20u64;
    println!("create transaction begin");
    // create transaction and capture transactionId from logs
    let tx_title = format!("tx-e2e-{}", run_nonce);
    let tx_receipt = send_tx_with_receipt(
        &provider_taker,
        pool,
        IPrivacyPool::createTransactionCall {
            offerSecretHash: U256::from(offer_secret_hash.0 as u64),
            cryptoAmount: U256::from(crypto_amount_u64),
            title: tx_title.clone(),
        }
        .abi_encode()
        .into(),
        "createTransaction",
    )
    .await
    .expect("createTransaction tx");
    println!("Create transaction end");

    let tx_created_sig = keccak256(b"TransactionCreated(bytes32,uint256,uint256,address)");

    let tx_id = tx_receipt
        .inner
        .logs()
        .iter()
        .find_map(|l| {
            let topics = l.topics();
            if topics.first().copied() == Some(tx_created_sig.into()) {
                topics.get(1).copied()
            } else {
                None
            }
        })
        .expect("TransactionCreated log topic1 (transactionId)");

    // Taker (buyer) paid fiat off-chain. Mock bank (Revolut) confirms the transfer.
    // The mock HTTP transcript simulates what TLSN would capture from the real bank API.
    let payout_secret = nonce_m31(0x3000_0001);
    let payout_nullifier = nonce_m31(0x3000_0002);
    let payout_secret_nullifier_hash = poseidon_hash_pair(payout_secret, payout_nullifier);
    let offer_fiat_u64 = offer_fiat.0 as u64;

    // Run a real TLSN session: prover makes MPC-TLS connection to the in-process mock bank,
    // verifier (notary) co-signs the session. The returned string is the actual raw HTTP
    // response captured from the notarized TLS transcript.
    let bank_transcript = tokio::task::spawn_blocking({
        let title = tx_title.clone();
        let rev = offer_rev_str.to_string();
        let fiat = offer_fiat_u64;
        move || run_tlsn_transfer_session(&title, &rev, fiat)
    })
    .await
    .expect("TLSN bank session");

    let settlement_sign_resp = reqwest::Client::new()
        .post(format!("{trusted_server_url}/verify-tlsn-and-sign-transaction-settlement"))
        .json(&VerifyTlsnAndSignTransactionSettlementRequest {
            transcript_response: bank_transcript,
            transaction_id_hex: format!("0x{}", hex::encode(tx_id.as_slice())),
            crypto_amount: crypto_amount_u64,
            secret_nullifier_hash: payout_secret_nullifier_hash.0 as u64,
            buyer_address: format!("0x{}", hex::encode(taker.as_slice())),
            token_address: format!("0x{}", hex::encode(token.as_slice())),
        })
        .send()
        .await
        .expect("settlement sign request");
    let settlement_sign_status = settlement_sign_resp.status();
    let settlement_sign_body = settlement_sign_resp
        .text()
        .await
        .expect("settlement sign response body");
    assert!(
        settlement_sign_status.is_success(),
        "settlement sign failed: status={}, body={}",
        settlement_sign_status,
        settlement_sign_body
    );
    let settlement_sign: VerifyTlsnAndSignTransactionSettlementResponse =
        serde_json::from_str(&settlement_sign_body).expect("settlement sign response json");

    println!("verify transaction begin");
    // verify transaction: TLSN settlement claim + offer_spend_cancel circuit proof
    let verify_receipt = send_tx_with_receipt(
        &provider_taker,
        pool,
        IPrivacyPool::verifyTransactionCall {
            transactionId: tx_id,
            fiatAmount: U256::from(settlement_sign.fiat_amount),
            cryptoAmount: U256::from(crypto_amount_u64),
            secretNullifierHash: U256::from(payout_secret_nullifier_hash.0 as u64),
            settlementSignature: Bytes::from(
                hex::decode(settlement_sign.signature_hex.trim_start_matches("0x"))
                    .expect("settlement signature hex"),
            ),
            offerCircuitOutputs: spend_payload.claim_output_values.clone(),
            offerCircuitSignature: Bytes::from(
                hex::decode(spend_sign.signature_hex.trim_start_matches("0x"))
                    .expect("spend circuit signature hex"),
            ),
        }
        .abi_encode()
        .into(),
        "verifyTransaction",
    )
    .await
    .expect("verifyTransaction tx");

    println!("After verify transaction");
    // -- verify use-once semantics --

    // 1. Deposit events in verifyTransaction receipt:
    //    - buyer gets crypto_amount
    //    - seller gets remaining (offer_amount - crypto_amount = 10) via offerRefundSnHash
    let deposit_sig = keccak256(b"Deposit(uint256,uint256,address,uint64,uint256)");
    let deposit_logs: Vec<_> = verify_receipt
        .inner
        .logs()
        .iter()
        .filter(|l| l.topics().first().copied() == Some(deposit_sig.into()))
        .collect();
    // expect exactly 2 Deposit events: buyer + seller refund
    assert_eq!(
        deposit_logs.len(),
        2,
        "expected 2 Deposit events in verifyTransaction receipt (buyer + seller refund), got {}",
        deposit_logs.len()
    );

    // 2. Offer is CANCELLED after first use — query contract state.
    let raw_offer = provider_taker
        .call(
            TransactionRequest::default()
                .to(pool)
                .input(IPrivacyPool::offersCall { secretHash: U256::from(offer_secret_hash.0 as u64) }.abi_encode().into()),
        )
        .await
        .expect("offers() call");
    let decoded_offer = IPrivacyPool::offersCall::abi_decode_returns(&raw_offer)
        .expect("decode offers()");
    // status 1 == CANCELLED
    assert_eq!(decoded_offer.status, 1u8, "offer should be CANCELLED after first use");
    println!("Create transaction must fail start");
    // 3. Creating a second transaction on the same (now-cancelled) offer must fail.
    // Use eth_call (read-only simulation) to avoid consuming a nonce on a reverting tx.
    // Sending a reverting tx via send_transaction leaves a stuck entry in the mempool,
    // which causes a nonce gap for the subsequent withdraw.
    let second_tx_call_result = provider_taker
        .call(
            TransactionRequest::default()
                .to(pool)
                .input(
                    IPrivacyPool::createTransactionCall {
                        offerSecretHash: U256::from(offer_secret_hash.0 as u64),
                        cryptoAmount: U256::from(1u64),
                        title: format!("tx-e2e-second-{}", run_nonce),
                    }
                    .abi_encode()
                    .into(),
                ),
        )
        .await;
    assert!(
        second_tx_call_result.is_err(),
        "second createTransaction on cancelled offer should revert (eth_call check)"
    );
    println!("After create transaction");
    // Withdraw created payout deposit.

    let taker_balance_before = IERC20::balanceOfCall { account: taker }
        .abi_encode();
    let raw_before = provider_taker
        .call(TransactionRequest::default().to(token).input(taker_balance_before.into()))
        .await
        .expect("balanceOf before call");
    let balance_before = IERC20::balanceOfCall::abi_decode_returns(&raw_before)
        .expect("decode balance before");

    let root_u256 = IPrivacyPool::getCurrentRootCall::abi_decode_returns(
        &provider_taker
            .call(
                TransactionRequest::default()
                    .to(pool)
                    .input(IPrivacyPool::getCurrentRootCall {}.abi_encode().into()),
            )
            .await
            .expect("get current root call"),
    )
    .expect("decode current root");
    let root_u32 = m31_u32(root_u256, "root");
    let nullifier_u32 = nonce_m31(0x4000_0001).0;
    let token_u32 = token_m31.0;
    let amount_u32 = crypto_amount_u64 as u32;
    let refund_commitment_u32 = 0u32;
    let recipient_u32 = address_to_m31(taker).0;

    let c_hash = withdraw_claim_hash(
        root_u32,
        nullifier_u32,
        token_u32,
        amount_u32,
        refund_commitment_u32,
        recipient_u32,
    );
    let m_hash = withdraw_message_hash(c_hash);
    let signer = Signer::from_private_key_hex(TRUSTED_SERVER_PRIVATE_KEY_HEX)
        .expect("trusted signer from key");
    let sig = signer.sign_digest(m_hash).expect("sign withdraw digest");

    let root = U256::from(root_u32 as u64);
    let nullifier = U256::from(nullifier_u32 as u64);
    let amount = U256::from(amount_u32 as u64);
    let refund_commitment_hash = U256::from(refund_commitment_u32 as u64);

    println!("Before withdraw");
    send_tx(
        &provider_taker,
        pool,
        IPrivacyPool::withdrawCall {
            root,
            nullifier,
            amount,
            refundCommitmentHash: refund_commitment_hash,
            signature: Bytes::from(sig.signature_65.to_vec()),
            token,
            recipient: taker,
        }
        .abi_encode()
        .into(),
        "withdraw",
    )
    .await;
    println!("After withdraw");
    let raw_after = provider_taker
        .call(TransactionRequest::default().to(token).input(IERC20::balanceOfCall { account: taker }.abi_encode().into()))
        .await
        .expect("balanceOf after call");
    let balance_after = IERC20::balanceOfCall::abi_decode_returns(&raw_after)
        .expect("decode balance after");

    assert_eq!(balance_after, balance_before + U256::from(crypto_amount_u64));
    assert!(owner != taker);
}
