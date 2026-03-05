use std::{net::SocketAddr, path::Path};

use async_compat::Compat;
use axum::body::Bytes;
use http_body_util::Empty;
use hyper::Request;
use quinn::Endpoint;
use shared::{
    TestQuicConfig, TestTlsConfig, get_or_create_test_quic_config, get_or_create_test_tls_config,
};
use smol::net::TcpStream;
use stwo_circuit::compute_commitment_hash;
use tlsnotary::{
    BodyFieldConfig, CertificateDer, Direction, HashAlgId, KeyValueCommitConfig, MpcTlsConfig,
    PlaintextHash, PlaintextHashSecret, Prover, RootCertStore, ServerName, TlsClientConfig,
    TlsCommitConfig, TranscriptCommitment, TranscriptSecret, prover::RevealConfig,
};
use tokio::io::join;

use crate::AppState;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const BALANCE_PADDING: usize = 12;

pub async fn run_tlsn_balance_query(app: &AppState) -> (Vec<u8>, [u8; 16], [u8; 32]) {
    let TestQuicConfig { client_config, .. } =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem"))
            .await
            .expect("Failed to load QUIC test config");
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

    tracing::info!("Opening QUIC bi stream for TLSN protocol");
    let (send, recv) = conn.open_bi().await.expect("Failed to open QUIC bi stream");
    let verifier_stream = join(recv, send);
    tracing::info!("Using raw QUIC stream for TLSN notarization");

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
    assert!(
        recomputed == commitment_hash,
        "TLSN commitment hash mismatch"
    );

    (fragment, blinder, commitment_hash)
}

pub fn parse_amount_from_fragment(fragment: &[u8]) -> u32 {
    let s = std::str::from_utf8(fragment).expect("Fragment is not valid UTF-8");
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        panic!(
            "Failed to parse amount from TLSN fragment: no digits found; raw_fragment={:?}",
            s
        );
    }
    digits.parse::<u32>().unwrap_or_else(|e| {
        panic!("Failed to parse amount from TLSN fragment: {e}; raw_fragment={s:?}")
    })
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
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}

fn create_response_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_fields: vec![BodyFieldConfig::Quoted(".username".into())],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![KeyValueCommitConfig::with_padding(
            ".balance".into(),
            BALANCE_PADDING,
        )],
    }
}
