use std::sync::OnceLock;

use axum::{body::Body, http::Request as AxumRequest};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use server::{
    app::{AppConfig, InitialUser, TransferRequest, TransferResponse, get_app},
    handle_connection,
};
use shared::{ATTESTATION_LEN, create_test_tls_config};
use smol::net::unix::UnixStream;
use tlsnotary::{
    CertificateDer, Direction, ExpectedValue, HashAlgId, MpcTlsConfig, Prover, ProverOutput,
    RootCertStore, ServerName, TlsClientConfig, TlsCommitConfig, TranscriptCommitment,
    TranscriptSecret, Validator, Verifier, VerifierConfig, prover::RevealConfig,
    verifier::VerifierOutput,
};
use tower::ServiceExt;

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

pub struct TestSockets {
    pub prover_server_socket: UnixStream,
    pub server_socket: UnixStream,
    pub prover_verifier_socket: UnixStream,
    pub verifier_socket: UnixStream,
}

pub fn create_test_sockets() -> TestSockets {
    let (prover_server_socket, server_socket) =
        UnixStream::pair().expect("prover/server socket pair");
    let (prover_verifier_socket, verifier_socket) =
        UnixStream::pair().expect("prover/verifier socket pair");

    TestSockets {
        prover_server_socket,
        server_socket,
        prover_verifier_socket,
        verifier_socket,
    }
}

pub fn create_test_request() -> Request<Empty<axum::body::Bytes>> {
    Request::builder()
        .method("GET")
        .uri("/api/attestations/1")
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::new())
        .expect("attestation request")
}

pub fn create_prover_config(cert_bytes: Vec<u8>) -> (TlsClientConfig, TlsCommitConfig) {
    let server_name = ServerName::Dns("localhost".to_string().try_into().expect("dns name"));

    let tls_client_config = TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()
        .expect("tls client config");

    let tls_commit_config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .expect("mpc tls config"),
        )
        .build()
        .expect("tls commit config");

    (tls_client_config, tls_commit_config)
}

pub fn create_verifier_config(cert_bytes: Vec<u8>) -> VerifierConfig {
    VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()
        .expect("verifier config")
}

pub fn create_request_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}

pub fn create_response_reveal_config() -> RevealConfig {
    use tlsnotary::{BodyFieldConfig, KeyValueCommitConfig};

    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_fields: vec![
            BodyFieldConfig::Quoted(".toUsername".into()),
            BodyFieldConfig::Unquoted(".eligibleForMint".into()),
        ],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![KeyValueCommitConfig::with_padding(
            ".attestation".into(),
            ATTESTATION_LEN,
        )],
    }
}

fn test_app() -> axum::Router {
    get_app(AppConfig {
        users: vec![
            InitialUser::new("alice", 100),
            InitialUser::new("bob", 40),
            InitialUser::new("treasury", 0),
        ],
        special_username: String::from("treasury"),
    })
    .expect("test app")
}

async fn seed_transfer(app: &axum::Router, to_username: &str) -> TransferResponse {
    let request = TransferRequest {
        from_username: String::from("alice"),
        to_username: String::from(to_username),
        amount: 25,
    };
    let response = app
        .clone()
        .oneshot(
            AxumRequest::builder()
                .method("POST")
                .uri("/api/transfers")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&request).expect("transfer request json"),
                ))
                .expect("transfer request"),
        )
        .await
        .expect("transfer response");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("transfer body")
        .to_bytes();
    serde_json::from_slice(&body).expect("transfer response json")
}

fn verify_prover_output(prover_output: &ProverOutput) {
    assert!(
        !prover_output.transcript_commitments.is_empty(),
        "prover should produce commitments"
    );
    assert!(
        !prover_output.transcript_secrets.is_empty(),
        "prover should produce secrets"
    );
}

fn verify_verifier_output_basic(verifier_output: &VerifierOutput) {
    assert_eq!(verifier_output.server_name, "localhost");

    let sent_data = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
        .expect("sent transcript should be valid utf-8");
    let received_data = String::from_utf8(verifier_output.transcript.received_unsafe().to_vec())
        .expect("received transcript should be valid utf-8");

    assert!(sent_data.contains("GET /api/attestations/1"));
    assert!(received_data.contains("\"toUsername\":\"treasury\""));
    assert!(received_data.contains("\"eligibleForMint\":true"));
}

fn verify_parsed_request(verifier_output: &VerifierOutput, sent_data: &str) {
    let parsed_request = verifier_output
        .parsed_request
        .as_ref()
        .expect("request should be parsed");
    let request_line = &sent_data[parsed_request.method.start..parsed_request.protocol_version.end];
    assert!(request_line.contains("GET /api/attestations/1 HTTP/1.1"));
}

fn verify_parsed_response(verifier_output: &VerifierOutput, received_data: &str) {
    let parsed_response = verifier_output
        .parsed_response
        .as_ref()
        .expect("response should be parsed");

    let status_line =
        &received_data[parsed_response.protocol_version.start..parsed_response.status.end];
    assert!(status_line.contains("HTTP/1.1 200 OK"));

    let to_username = parsed_response
        .body
        .get(".toUsername")
        .expect("toUsername should be revealed");
    match to_username {
        parser::redacted::Body::KeyValue {
            value: Some(value), ..
        } => {
            assert_eq!(&received_data[value.clone()], "treasury");
        }
        _ => panic!("toUsername should be revealed"),
    }

    let attestation = parsed_response
        .body
        .get(".attestation")
        .expect("attestation field should be present");
    match attestation {
        parser::redacted::Body::KeyValue { value, .. } => {
            assert!(value.is_none(), "attestation value should remain committed");
        }
        _ => panic!("attestation should be a key/value field"),
    }
}

fn verify_attestation_commitment_and_proof(
    verifier_output: &VerifierOutput,
    proof: &crate::Proof,
) -> crate::Result<()> {
    let parsed_response = verifier_output
        .parsed_response
        .as_ref()
        .expect("response should be parsed");
    let bindings =
        crate::bind_commitments_to_keys(parsed_response, &verifier_output.transcript_commitments)?;
    let attestation_binding = bindings
        .get(".attestation")
        .expect("attestation binding should exist");
    let mut commitment_hash = [0u8; 32];
    commitment_hash.copy_from_slice(attestation_binding.hash.hash.value.as_bytes());
    crate::verify_proof_against_hash(proof, &commitment_hash)
}

fn setup_srs() {
    static SRS: OnceLock<()> = OnceLock::new();

    SRS.get_or_init(|| {
        shared::init_test_logging();
        crate::setup_barretenberg_srs().expect("failed to setup Barretenberg SRS");
    });
}

fn run_end_to_end_flow(to_username: &str) -> (ProverOutput, VerifierOutput) {
    setup_srs();

    smol::block_on(async {
        let test_tls_config = create_test_tls_config().expect("test tls config");
        let sockets = create_test_sockets();
        let (tls_client_config, tls_commit_config) =
            create_prover_config(test_tls_config.cert_bytes.clone());
        let verifier_config = create_verifier_config(test_tls_config.cert_bytes);
        let app = test_app();
        let _transfer = seed_transfer(&app, to_username).await;
        let server_task =
            handle_connection(app, test_tls_config.server_config, sockets.server_socket);

        let prover = Prover::builder()
            .tls_client_config(tls_client_config)
            .tls_commit_config(tls_commit_config)
            .request(create_test_request())
            .request_reveal_config(create_request_reveal_config())
            .response_reveal_config(create_response_reveal_config())
            .build()
            .expect("prover");

        let verifier = Verifier::builder()
            .verifier_config(verifier_config)
            .build()
            .expect("verifier");

        let prover_task =
            prover.prove(sockets.prover_verifier_socket, sockets.prover_server_socket);
        let verifier_task = verifier.verify(sockets.verifier_socket);
        let (server_result, prover_result, verifier_result) =
            futures::join!(server_task, prover_task, verifier_task);

        server_result.expect("server should complete");
        (
            prover_result.expect("prover should complete"),
            verifier_result.expect("verifier should complete"),
        )
    })
}

#[test]
fn test_end_to_end_proof_generation_verification_and_zkproof_generation() {
    let (prover_output, verifier_output) = run_end_to_end_flow("treasury");

    verify_prover_output(&prover_output);
    verify_verifier_output_basic(&verifier_output);

    let sent_data = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
        .expect("sent transcript should be valid utf-8");
    let received_data = String::from_utf8(verifier_output.transcript.received_unsafe().to_vec())
        .expect("received transcript should be valid utf-8");

    verify_parsed_request(&verifier_output, &sent_data);
    verify_parsed_response(&verifier_output, &received_data);

    let bundle = crate::generate_settlement_bundle(
        &prover_output.transcript_commitments,
        &prover_output.transcript_secrets,
        &prover_output.received,
        crate::PaddingConfig::new(ATTESTATION_LEN),
    )
    .expect("settlement bundle should be generated");

    verify_attestation_commitment_and_proof(&verifier_output, &bundle.native_proof)
        .expect("attestation commitment should match proof");
}

#[test]
fn test_derive_noir_prover_inputs_renders_nargo_inputs() {
    let (prover_output, _) = run_end_to_end_flow("treasury");

    let inputs = crate::derive_noir_prover_inputs(
        &prover_output.transcript_commitments,
        &prover_output.transcript_secrets,
        &prover_output.received,
        crate::PaddingConfig::new(ATTESTATION_LEN),
    )
    .expect("Noir inputs should be derived");

    assert_eq!(inputs.attestation_committed_hash.len(), 32);
    assert_eq!(inputs.attestation_blinder.len(), 16);
    assert_eq!(inputs.attestation.len(), ATTESTATION_LEN);

    let prover_toml = inputs.to_prover_toml();
    assert!(prover_toml.contains("attestation_blinder = [\""));
    assert!(prover_toml.contains("attestation_committed_hash = [\""));
    assert!(prover_toml.contains("attestation = \""));
    assert!(prover_toml.contains("tx_id = \"1\""));
    assert!(prover_toml.contains("amount = \"25\""));
}

#[test]
fn test_derive_noir_prover_inputs_rejects_invalid_inputs() {
    let (prover_output, _) = run_end_to_end_flow("treasury");
    let padding_config = crate::PaddingConfig::new(ATTESTATION_LEN);

    let truncated_err = crate::derive_noir_prover_inputs(
        &prover_output.transcript_commitments,
        &prover_output.transcript_secrets,
        &prover_output.received[..8],
        padding_config.clone(),
    )
    .expect_err("truncated transcript should be rejected");
    assert!(matches!(truncated_err, crate::ZkTlsnError::InvalidInput(_)));

    let mut bad_direction_commitments = prover_output.transcript_commitments.clone();
    mutate_received_hash_commitment(&mut bad_direction_commitments, |hash| {
        hash.direction = Direction::Sent;
    });
    let direction_err = crate::derive_noir_prover_inputs(
        &bad_direction_commitments,
        &prover_output.transcript_secrets,
        &prover_output.received,
        padding_config.clone(),
    )
    .expect_err("sent-direction commitment should be rejected");
    assert!(matches!(
        direction_err,
        crate::ZkTlsnError::NoReceivedCommitments
    ));

    let mut bad_algorithm_secrets = prover_output.transcript_secrets.clone();
    mutate_received_hash_secret(&mut bad_algorithm_secrets, |hash| {
        hash.alg = HashAlgId::SHA256;
    });
    let algorithm_err = crate::derive_noir_prover_inputs(
        &prover_output.transcript_commitments,
        &bad_algorithm_secrets,
        &prover_output.received,
        padding_config,
    )
    .expect_err("non-BLAKE3 secret should be rejected");
    assert!(matches!(
        algorithm_err,
        crate::ZkTlsnError::InvalidCommitmentDirection
    ));
}

#[test]
fn test_tlsnotary_validator_tracks_attestation_response() {
    let (_, verifier_output) = run_end_to_end_flow("treasury");

    let validator = Validator::builder()
        .expected_server_name("localhost")
        .expected_hash_alg(HashAlgId::BLAKE3)
        .request_header_equals("content-type", "application/json")
        .response_body_field_equals(
            ".toUsername",
            ExpectedValue::String(String::from("treasury")),
        )
        .response_body_field_equals(".eligibleForMint", ExpectedValue::Bool(true))
        .build();

    validator
        .validate(&verifier_output)
        .expect("validator should accept attestation response");
}

fn mutate_received_hash_commitment(
    commitments: &mut [TranscriptCommitment],
    mutate: impl FnOnce(&mut tlsnotary::PlaintextHash),
) {
    let hash = commitments
        .iter_mut()
        .find_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .expect("received hash commitment");
    mutate(hash);
}

fn mutate_received_hash_secret(
    secrets: &mut [TranscriptSecret],
    mutate: impl FnOnce(&mut tlsnotary::PlaintextHashSecret),
) {
    let hash = secrets
        .iter_mut()
        .find_map(|secret| match secret {
            TranscriptSecret::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .expect("received hash secret");
    mutate(hash);
}
