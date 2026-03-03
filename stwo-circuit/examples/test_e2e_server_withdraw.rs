use alloy::primitives::{Address, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use async_compat::Compat;
use axum::body::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, path::Path};
use clap::Parser;
use quinn::Endpoint;
use serde::Deserialize;
use shared::{TestQuicConfig, TestTlsConfig, get_or_create_test_quic_config, get_or_create_test_tls_config};
use smol::net::TcpStream;
use tlsnotary::{
    BodyFieldConfig, CertificateDer, Direction, HashAlgId, KeyValueCommitConfig, MpcTlsConfig,
    PlaintextHash, PlaintextHashSecret, Prover, RootCertStore, ServerName, TlsClientConfig,
    TlsCommitConfig, TranscriptCommitment, TranscriptSecret,
    prover::RevealConfig,
};
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    WithdrawInputs, build_onchain_verification_input, build_verify_calldata, compute_commitment_hash,
    prove_withdraw, simulate_withdraw_with_proof_call, verify_withdraw,
};
use stwo_circuit::offchain_merkle::OffchainMerkleTree;
use alloy::rpc::types::Filter;
use tokio::io::{AsyncRead, AsyncWrite, join};
use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use stwo_circuit::poseidon_chain::{ChainInputs, gen_poseidon_chain_trace};

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const BALANCE_PADDING: usize = 12;
const MERKLE_SIBLING_DEPTH: usize = 31;
const M31_MODULUS: u32 = 2_147_483_647;
const ANVIL_TOPUP_BALANCE_HEX: &str = "0x3635C9ADC5DEA000000000";

#[derive(Debug, Parser)]
#[command(name = "test_e2e_server_withdraw")]
struct AppState {
    #[arg(long, env = "RPC_URL", default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    #[arg(long, env = "VERIFIER_ADDRESS")]
    verifier_address: Address,
    #[arg(long, env = "PRIVACY_POOL_ADDRESS")]
    privacy_pool_address: Address,
    #[arg(long, env = "WITHDRAW_TOKEN")]
    withdraw_token: Address,
    #[arg(long, env = "TLSN_VERIFIER_ADDR", default_value = "[::1]:5000")]
    tlsn_verifier_addr: String,
    #[arg(long, env = "TLS_SERVER_ADDR", default_value = "localhost:8443")]
    tls_server_addr: String,
    #[arg(
        long,
        env = "WITHDRAW_RECIPIENT",
        default_value = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    )]
    withdraw_recipient: Address,
    #[arg(
        long,
        env = "POOL_OWNER_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    owner_private_key: String,
    #[arg(long, env = "WITHDRAW_SECRET", default_value_t = 12345u32)]
    withdraw_secret: u32,
    #[arg(long, env = "WITHDRAW_NULLIFIER", default_value_t = 67890u32)]
    withdraw_nullifier: u32,
    #[arg(long, env = "WITHDRAW_GAS_LIMIT", default_value_t = 12_000_000_000_000u64)]
    withdraw_gas_limit: u64,
    #[arg(long, env = "WITHDRAW_MAX_FEE_PER_GAS", default_value_t = 2_000_000_000u128)]
    withdraw_max_fee_per_gas: u128,
    #[arg(
        long,
        env = "WITHDRAW_MAX_PRIORITY_FEE_PER_GAS",
        default_value_t = 1_000_000_000u128
    )]
    withdraw_max_priority_fee_per_gas: u128,
}

impl AppState {
    fn from_env() -> Self {
        Self::parse()
    }
}

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    interface IPrivacyPool {
        function setVerifier(address verifier) external;
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function withdraw(
            uint256 root,
            uint256 nullifier,
            address token,
            uint256 amount,
            address recipient,
            bytes calldata verifyCalldata
        ) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    session_id: String,
}

fn main() {
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
        tracing::info!("Step 1: Running TLSN and extracting committed balance + blinder");
        let (balance_fragment, blinder, commitment_hash) = run_tlsn_balance_query(&app).await;
        let parsed_amount = parse_amount_from_fragment(&balance_fragment);
        tracing::info!(parsed_amount, "Amount extracted from TLSN committed fragment");
        let amount = BaseField::from_u32_unchecked(parsed_amount);
        let token_address = BaseField::from_u32_unchecked(address_to_m31(app.withdraw_token));

    tracing::info!("Step 2: Preparing pool state and performing real deposit");

    ensure_owner_has_eth_for_gas(&app).await;

    send_set_verifier_tx(&app).await.expect("Failed to send setVerifier tx");
    let mut offchain_tree = build_offchain_merkle_tree(&app).await;
    let merkle_index_onchain = call_next_leaf_index(&app).await as u32;
    let merkle_index = u32::try_from(offchain_tree.leaf_count())
        .unwrap_or_else(|_| panic!("Off-chain tree leaf_count does not fit u32"));
    assert_eq!(
        merkle_index, merkle_index_onchain,
        "Off-chain leaf count mismatch with contract next index"
    );
    let effective_secret_u32 = app.withdraw_secret.wrapping_add(merkle_index);
    let effective_nullifier_u32 = app.withdraw_nullifier.wrapping_add(merkle_index);
    let secret = BaseField::from_u32_unchecked(effective_secret_u32);
    let nullifier = BaseField::from_u32_unchecked(effective_nullifier_u32);
    tracing::info!(
        merkle_index,
        effective_secret = effective_secret_u32,
        effective_nullifier = effective_nullifier_u32,
        "Using per-run secret/nullifier derived from merkle index"
    );

    let deposit_inputs = ChainInputs::for_deposit(secret, nullifier, amount, token_address);
    let (_, deposit_outputs) = gen_poseidon_chain_trace(4, deposit_inputs);
    let offchain_index = offchain_tree.add_leaf(deposit_outputs.leaf);
    assert_eq!(offchain_index as u32, merkle_index, "Off-chain inserted index mismatch");
    let (merkle_siblings, _) = offchain_tree.path(offchain_index as usize);
    let expected_root = offchain_tree.root();

    let secret_nullifier_hash = deposit_outputs.secret_nullifier_hash;
    let deposit_amount_u64 = amount.0 as u64;
    tracing::info!(merkle_depth = MERKLE_SIBLING_DEPTH, "Built Merkle siblings from off-chain tree");

    send_approve_tx(&app, U256::from(deposit_amount_u64)).await.expect("Failed to send approve tx");
    send_deposit_tx(&app, U256::from(secret_nullifier_hash.0), U256::from(deposit_amount_u64))
        .await
        .expect("Failed to send deposit tx");

    let merkle_root_u256 = call_current_root(&app).await;
    let merkle_root_u32 = u32::try_from(merkle_root_u256)
        .unwrap_or_else(|_| panic!("Current root doesn't fit M31/u32: {merkle_root_u256}"));
    let merkle_root = BaseField::from_u32_unchecked(merkle_root_u32);
    assert_eq!(merkle_root, expected_root, "On-chain root mismatch vs off-chain reconstructed root");

    let inputs = WithdrawInputs {
        balance_fragment,
        blinder,
        commitment_hash,
        secret,
        nullifier,
        amount,
        token_address,
        merkle_siblings,
        merkle_index,
        merkle_root,
    };

    tracing::info!("Step 3: Generating combined proof");
    let proof = prove_withdraw(inputs, 8).expect("Proof generation failed");
    verify_withdraw(proof.clone()).expect("Off-chain verification failed");

    tracing::info!("Step 4: Building on-chain verification payload");
    let verify_input = build_onchain_verification_input(&proof).expect("Failed to build onchain input");
    let verify_calldata = build_verify_calldata(&verify_input);

    tracing::info!("Step 5: Calling real PrivacyPool.withdraw transaction");
    simulate_withdraw_with_proof_call(
        &app.rpc_url,
        app.privacy_pool_address,
        U256::from(proof.merkle_root.0),
        U256::from(proof.nullifier.0),
        app.withdraw_token,
        U256::from(proof.amount.0),
        app.withdraw_recipient,
        &verify_input,
    )
    .unwrap_or_else(|e| panic!("Preflight withdraw simulation failed: {e}"));

    send_withdraw_tx(
        &app,
        U256::from(proof.merkle_root.0),
        U256::from(proof.nullifier.0),
        U256::from(proof.amount.0),
        verify_calldata,
    )
    .await
    .expect("Failed to send withdraw transaction");

        tracing::info!("✅ Full E2E passed: deposit -> server amount -> proof -> withdraw");
    });
}

async fn run_tlsn_balance_query(app: &AppState) -> (Vec<u8>, [u8; 16], [u8; 32]) {
    let TestQuicConfig { client_config, .. } =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await;
    let addr: SocketAddr = "[::]:0".parse().unwrap();
    let mut endpoint = Endpoint::client(addr).expect("Failed to create QUIC client endpoint");
    endpoint.set_default_client_config(client_config);

    let verifier_addr: SocketAddr = app
        .tlsn_verifier_addr
        .parse()
        .expect("Invalid TLSN verifier address");
    tracing::info!(%verifier_addr, "Connecting to TLSN verifier");
    let conn = endpoint
        .connect(verifier_addr, "localhost")
        .expect("Failed to create QUIC connection")
        .await
        .expect("Failed to connect to TLSN verifier");
    tracing::info!("Connected to TLSN verifier");

    tracing::info!("Opening QUIC bi stream for /session");
    let (send, recv) = conn.open_bi().await.expect("Failed to open QUIC bi stream");
    let stream = join(recv, send);
    tracing::info!("Sending /session request");
    let (status_code, response_bytes) =
        send_post_request(stream, Uri::from_static("/session"), Bytes::new()).await;
    assert_eq!(status_code, StatusCode::OK, "Session request failed");
    let session_response: SessionResponse =
        serde_json::from_slice(&response_bytes).expect("Failed to parse /session response");
    tracing::info!(session_id = %session_response.session_id, "Got TLSN session id");

    tracing::info!("Opening QUIC bi stream for /notarize upgrade");
    let (send, recv) = conn.open_bi().await.expect("Failed to open QUIC bi stream");
    let stream = join(recv, send);
    let notarize_uri: Uri = format!("/notarize?sessionId={}", session_response.session_id)
        .parse()
        .expect("Invalid notarize URI");
    tracing::info!("Sending /notarize upgrade request");
    let verifier_stream = send_upgrade_request(stream, notarize_uri).await;
    tracing::info!("Got upgraded notarization stream");

    tracing::info!(server_addr = %app.tls_server_addr, "Connecting to TLS server");
    let prover_server_socket = TcpStream::connect(&app.tls_server_addr)
        .await
        .expect("Failed to connect to external TLS server");

    let TestTlsConfig { cert_bytes, .. } =
        get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))
            .expect("Failed to load TLS test certs");
    let (tls_client_config, tls_commit_config) = create_prover_config(cert_bytes);

    let prover = Prover::builder()
        .tls_client_config(tls_client_config)
        .tls_commit_config(tls_commit_config)
        .request(create_test_request())
        .request_reveal_config(create_request_reveal_config())
        .response_reveal_config(create_response_reveal_config())
        .build()
        .expect("Failed to build TLSN prover");

    tracing::info!("Running TLSN prover");
    let prover_output = prover
        .prove(Compat::new(verifier_stream), prover_server_socket)
        .await
        .expect("TLSN prover failed");

    let commitment = extract_received_commitment(&prover_output.transcript_commitments);
    let secret = extract_received_secret(&prover_output.transcript_secrets);
    prepare_proof_input(&prover_output.received, &commitment, &secret)
}

fn extract_received_commitment(commitments: &[TranscriptCommitment]) -> PlaintextHash {
    commitments
        .iter()
        .find_map(|c| match c {
            TranscriptCommitment::Hash(h) if h.direction == Direction::Received => Some(h.clone()),
            _ => None,
        })
        .expect("No received transcript commitment")
}

fn extract_received_secret(secrets: &[TranscriptSecret]) -> PlaintextHashSecret {
    secrets
        .iter()
        .find_map(|s| match s {
            TranscriptSecret::Hash(h) if h.direction == Direction::Received => Some(h.clone()),
            _ => None,
        })
        .expect("No received transcript secret")
}

fn prepare_proof_input(
    received_data: &[u8],
    commitment: &PlaintextHash,
    secret: &PlaintextHashSecret,
) -> (Vec<u8>, [u8; 16], [u8; 32]) {
    assert!(
        commitment.direction == Direction::Received && commitment.hash.alg == HashAlgId::BLAKE3,
        "Invalid commitment type for received data"
    );
    assert!(
        secret.direction == Direction::Received && secret.alg == HashAlgId::BLAKE3,
        "Invalid secret type for received data"
    );

    let range = commitment.idx.min().unwrap()..commitment.idx.end().unwrap();
    assert!(
        range.len() == BALANCE_PADDING,
        "Unexpected committed balance fragment length: {}",
        range.len()
    );

    let fragment = received_data
        .get(range)
        .expect("Committed range is out of bounds in received data")
        .to_vec();

    let blinder: [u8; 16] = secret
        .blinder
        .as_bytes()
        .try_into()
        .expect("TLSN blinder length must be 16");

    let commitment_hash: [u8; 32] = commitment
        .hash
        .value
        .as_bytes()
        .try_into()
        .expect("TLSN commitment hash length must be 32");

    let recomputed = compute_commitment_hash(&fragment, &blinder);
    assert!(recomputed == commitment_hash, "TLSN commitment hash mismatch");

    (fragment, blinder, commitment_hash)
}

fn parse_amount_from_fragment(fragment: &[u8]) -> u32 {
    let s = std::str::from_utf8(fragment).expect("Fragment is not valid UTF-8");
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        panic!(
            "Failed to parse amount from TLSN fragment: no digits found; raw_fragment={:?}",
            s
        );
    }
    digits
        .parse::<u32>()
        .unwrap_or_else(|e| panic!("Failed to parse amount from TLSN fragment: {e}; raw_fragment={s:?}"))
}

fn create_test_request() -> Request<Empty<Bytes>> {
    Request::builder()
        .method("GET")
        .uri("/api/balance/alice")
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .expect("Failed to build test request")
}

fn create_prover_config(cert_bytes: Vec<u8>) -> (TlsClientConfig, TlsCommitConfig) {
    let server_name = ServerName::Dns("localhost".to_string().try_into().unwrap());

    let tls_client_config = TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()
        .unwrap();

    let tls_commit_config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    (tls_client_config, tls_commit_config)
}

fn create_request_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_keypaths: vec![],
        commit_body_keypaths: vec![],
        reveal_key_commit_value_keypaths: vec![],
    }
}

fn create_response_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_keypaths: vec![BodyFieldConfig::Quoted(".username".into())],
        commit_body_keypaths: vec![],
        reveal_key_commit_value_keypaths: vec![KeyValueCommitConfig::with_padding(
            ".balance".into(),
            BALANCE_PADDING,
        )],
    }
}

async fn send_set_verifier_tx(app: &AppState) -> Result<(), String> {
    let calldata = IPrivacyPool::setVerifierCall {
        verifier: app.verifier_address,
    }
    .abi_encode();
    send_simple_tx(app, app.privacy_pool_address, calldata.into(), "setVerifier").await
}

async fn send_approve_tx(app: &AppState, amount: U256) -> Result<(), String> {
    let calldata = IERC20::approveCall {
        spender: app.privacy_pool_address,
        amount,
    }
    .abi_encode();
    send_simple_tx(app, app.withdraw_token, calldata.into(), "approve").await
}

async fn send_deposit_tx(app: &AppState, secret_nullifier_hash: U256, amount: U256) -> Result<(), String> {
    let calldata = IPrivacyPool::depositCall {
        secretNullifierHash: secret_nullifier_hash,
        amount,
        token: app.withdraw_token,
    }
    .abi_encode();
    send_simple_tx(app, app.privacy_pool_address, calldata.into(), "deposit").await
}

async fn send_simple_tx(
    app: &AppState,
    to: Address,
    input: alloy::primitives::Bytes,
    label: &str,
) -> Result<(), String> {
    let owner_private_key = app.owner_private_key.clone();
    let rpc_url = app.rpc_url.clone();
    let max_fee = app.withdraw_max_fee_per_gas;
    let max_priority = app.withdraw_max_priority_fee_per_gas;
    let label = label.to_string();

    Compat::new(async move {
        let signer: PrivateKeySigner = owner_private_key
            .parse()
            .map_err(|e| format!("Invalid private key: {e}"))?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(
                rpc_url
                    .parse()
                    .map_err(|e| format!("Invalid RPC URL: {e}"))?,
            );

        let tx = TransactionRequest::default()
            .to(to)
            .input(input.into())
            .max_fee_per_gas(max_fee)
            .max_priority_fee_per_gas(max_priority);

        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("{label} send_transaction failed: {e}"))?;

        let receipt = tokio::time::timeout(Duration::from_secs(120), pending.get_receipt())
            .await
            .map_err(|_| format!("{label} get_receipt timed out after 120s"))?
            .map_err(|e| format!("{label} receipt failed: {e}"))?;

        if !receipt.status() {
            return Err(format!(
                "{label} transaction reverted, tx hash: {}, gas_used: {:?}",
                receipt.transaction_hash, receipt.gas_used
            ));
        }

        Ok(())
    })
    .await
}

async fn send_post_request<IO>(stream: IO, uri: Uri, body: Bytes) -> (StatusCode, Vec<u8>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream)
        .await
        .expect("HTTP handshake failed");

    let request_task = async move {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(body))
            .expect("Failed to build HTTP request");

        let res = sender.send_request(req).await.expect("HTTP send failed");
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .expect("Failed to read HTTP body")
            .to_bytes()
            .to_vec();
        (status, body)
    };

    let (conn_result, response) = futures::join!(conn, request_task);
    conn_result.expect("HTTP connection failed");
    response
}

async fn send_upgrade_request<IO>(stream: IO, uri: Uri) -> impl AsyncRead + AsyncWrite + Unpin
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream)
        .await
        .expect("HTTP handshake failed");

    smol::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::error!("Connection error: {:?}", e);
        }
    })
    .detach();

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Connection", "Upgrade")
        .header("Upgrade", "tcp")
        .body(Empty::<Bytes>::new())
        .expect("Failed to build upgrade request");

    let res = sender.send_request(request).await.expect("Upgrade request failed");
    tracing::info!("Upgrade response status: {}", res.status());

    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .expect("Failed to read upgrade error body")
            .to_bytes();
        panic!(
            "Upgrade failed with status {} and body {}",
            status,
            String::from_utf8_lossy(&body)
        );
    }

    let upgraded = hyper::upgrade::on(res)
        .await
        .expect("Failed to obtain upgraded stream");
    TokioIo::new(upgraded)
}

async fn send_withdraw_tx(
    app: &AppState,
    root: U256,
    nullifier: U256,
    amount: U256,
    verify_calldata: alloy::primitives::Bytes,
) -> Result<(), String> {
    let owner_private_key = app.owner_private_key.clone();
    let rpc_url = app.rpc_url.clone();
    let withdraw_token = app.withdraw_token;
    let withdraw_recipient = app.withdraw_recipient;
    let privacy_pool_address = app.privacy_pool_address;
    let withdraw_gas_limit = app.withdraw_gas_limit;
    let max_fee = app.withdraw_max_fee_per_gas;
    let max_priority = app.withdraw_max_priority_fee_per_gas;

    Compat::new(async move {
        let signer: PrivateKeySigner = owner_private_key
            .parse()
            .map_err(|e| format!("Invalid private key: {e}"))?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(
                rpc_url
                    .parse()
                    .map_err(|e| format!("Invalid RPC URL: {e}"))?,
            );

        let call_data = IPrivacyPool::withdrawCall {
            root,
            nullifier,
            token: withdraw_token,
            amount,
            recipient: withdraw_recipient,
            verifyCalldata: verify_calldata,
        };

        let tx = TransactionRequest::default()
            .to(privacy_pool_address)
            .input(call_data.abi_encode().into())
            .gas_limit(withdraw_gas_limit)
            .max_fee_per_gas(max_fee)
            .max_priority_fee_per_gas(max_priority);

        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("withdraw send_transaction failed: {e}"))?;

        let receipt = tokio::time::timeout(Duration::from_secs(300), pending.get_receipt())
            .await
            .map_err(|_| "withdraw get_receipt timed out after 300s".to_string())?
            .map_err(|e| format!("withdraw receipt failed: {e}"))?;

        if !receipt.status() {
            let call_err = provider
                .call(
                    TransactionRequest::default()
                        .to(privacy_pool_address)
                        .input(call_data.abi_encode().into()),
                )
                .await
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown (eth_call returned success)".to_string());
            return Err(format!(
                "withdraw transaction reverted, tx hash: {}, gas_used: {:?}, preflight_error: {}",
                receipt.transaction_hash,
                receipt.gas_used,
                call_err
            ));
        }

        Ok(())
    })
    .await
}

fn address_to_m31(address: Address) -> u32 {
    let address_u256 = U256::from_be_slice(address.as_slice());
    let reduced = address_u256 % U256::from(M31_MODULUS);
    u32::try_from(reduced).expect("Address modulo M31 should fit into u32")
}

async fn call_next_leaf_index(app: &AppState) -> u64 {
    let data = IPrivacyPool::getNextLeafIndexCall {}.abi_encode();
    let raw = run_eth_call(app, app.privacy_pool_address, data.into())
        .await
        .unwrap_or_else(|e| panic!("getNextLeafIndex call failed: {e}"));
    let decoded = IPrivacyPool::getNextLeafIndexCall::abi_decode_returns(&raw)
        .unwrap_or_else(|e| panic!("Failed to decode getNextLeafIndex return: {e}"));
    decoded
}

async fn call_current_root(app: &AppState) -> U256 {
    let data = IPrivacyPool::getCurrentRootCall {}.abi_encode();
    let raw = run_eth_call(app, app.privacy_pool_address, data.into())
        .await
        .unwrap_or_else(|e| panic!("getCurrentRoot call failed: {e}"));
    let decoded = IPrivacyPool::getCurrentRootCall::abi_decode_returns(&raw)
        .unwrap_or_else(|e| panic!("Failed to decode getCurrentRoot return: {e}"));
    decoded
}

async fn build_offchain_merkle_tree(app: &AppState) -> OffchainMerkleTree {
    let rpc_url = app.rpc_url.clone();
    let privacy_pool = app.privacy_pool_address;

    let logs = Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );
        let deposit_filter = Filter::new()
            .address(privacy_pool)
            .from_block(0u64)
            .event("Deposit(uint256,uint256,address,uint64,uint256)");
        let mut logs = provider
            .get_logs(&deposit_filter)
            .await
            .map_err(|e| format!("Failed to fetch deposit logs: {e}"))?;

        if logs.is_empty() {
            let leaf_filter = Filter::new()
                .address(privacy_pool)
                .from_block(0u64)
                .event("LeafAdded(address,uint256,uint256)");
            logs = provider
                .get_logs(&leaf_filter)
                .await
                .map_err(|e| format!("Failed to fetch leaf logs: {e}"))?;
        }

        Ok::<_, String>(logs)
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    let mut sorted_logs = logs;
    sorted_logs.sort_by_key(|log| (log.block_number.unwrap_or_default(), log.log_index.unwrap_or_default()));

    let mut tree = OffchainMerkleTree::new(MERKLE_SIBLING_DEPTH);
    for log in sorted_logs {
        let commitment_topic = log
            .inner
            .topics()
            .get(1)
            .unwrap_or_else(|| panic!("Deposit log missing indexed commitment topic"));
        let commitment_u256 = U256::from_be_slice(commitment_topic.as_slice());
        let commitment_u32 = u32::try_from(commitment_u256).unwrap_or_else(|_| {
            panic!("Deposit commitment does not fit u32/M31: {commitment_u256}")
        });
        tree.add_leaf(BaseField::from_u32_unchecked(commitment_u32));
    }
    tree
}

async fn ensure_owner_has_eth_for_gas(app: &AppState) {
    let owner_private_key = app.owner_private_key.clone();
    let rpc_url = app.rpc_url.clone();

    Compat::new(async move {
        let signer: PrivateKeySigner = owner_private_key
            .parse()
            .unwrap_or_else(|e| panic!("Invalid private key: {e}"));
        let owner = signer.address();
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .unwrap_or_else(|e| panic!("Invalid RPC URL: {e}")),
        );
        let target_balance = U256::from_str_radix(
            ANVIL_TOPUP_BALANCE_HEX.trim_start_matches("0x"),
            16,
        )
        .unwrap_or_else(|e| panic!("Invalid ANVIL_TOPUP_BALANCE_HEX: {e}"));

        match provider.anvil_set_balance(owner, target_balance).await {
            Ok(()) => tracing::info!(owner = %owner, "Topped up owner ETH balance on Anvil"),
            Err(e) => tracing::warn!(
                owner = %owner,
                err = %e,
                "Failed to top up owner ETH balance (continuing)"
            ),
        }
    })
    .await;
}

async fn run_eth_call(
    app: &AppState,
    to: Address,
    input: alloy::primitives::Bytes,
) -> Result<alloy::primitives::Bytes, String> {
    let rpc_url = app.rpc_url.clone();

    Compat::new(async move {
        let provider = ProviderBuilder::new().connect_http(
            rpc_url
                .parse()
                .map_err(|e| format!("Invalid RPC URL: {e}"))?,
        );
        provider
            .call(
                TransactionRequest::default()
                    .to(to)
                    .input(input.into()),
            )
            .await
            .map_err(|e| e.to_string())
    })
    .await
}
