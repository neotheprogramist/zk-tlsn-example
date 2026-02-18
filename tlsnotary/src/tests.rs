//! Test utilities for tlsnotary integration tests
//!
//! This module provides reusable components for testing the TLSN protocol
//! end-to-end, including socket setup, configuration builders, and verification helpers.

use std::collections::HashMap;

/// Maximum sent data size for tests (4 KB)
pub const MAX_SENT_DATA: usize = 1 << 12;
/// Maximum received data size for tests (16 KB)
pub const MAX_RECV_DATA: usize = 1 << 14;

use axum::body::Bytes;
use http_body_util::Empty;
use hyper::Request;
use smol::net::unix::UnixStream;

use crate::{
    CertificateDer, ExpectedValue, ProtocolConfig, ProtocolConfigValidator, ProverConfig,
    ProverOutput, RootCertStore, ServerName, TlsConfig, Validator, VerifierConfig,
    prover::RevealConfig, verifier::VerifierOutput,
};

/// Socket pairs for prover-server and prover-verifier communication
pub struct TestSockets {
    pub prover_server_socket: UnixStream,
    pub server_socket: UnixStream,
    pub prover_verifier_socket: UnixStream,
    pub verifier_socket: UnixStream,
}

/// Creates Unix socket pairs for testing
pub fn create_test_sockets() -> TestSockets {
    let (prover_server_socket, server_socket) = UnixStream::pair().unwrap();
    let (prover_verifier_socket, verifier_socket) = UnixStream::pair().unwrap();

    TestSockets {
        prover_server_socket,
        server_socket,
        prover_verifier_socket,
        verifier_socket,
    }
}

/// Creates a test HTTP request for balance API endpoint
pub fn create_test_request() -> Request<Empty<Bytes>> {
    Request::builder()
        .method("GET")
        .uri("/api/balance/alice")
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .expect("Failed to build request")
}

/// Creates prover configuration with test TLS settings
pub fn create_prover_config(cert_bytes: Vec<u8>) -> ProverConfig {
    let server_name = ServerName::Dns("localhost".to_string().try_into().unwrap());

    let mut tls_config_builder = TlsConfig::builder();
    tls_config_builder.root_store(RootCertStore {
        roots: vec![CertificateDer(cert_bytes)],
    });
    let tls_config = tls_config_builder.build().unwrap();

    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(server_name)
        .tls_config(tls_config)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .unwrap(),
        );

    prover_config_builder.build().unwrap()
}

/// Creates verifier configuration with test TLS settings
pub fn create_verifier_config(cert_bytes: Vec<u8>) -> VerifierConfig {
    VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

/// Creates reveal configuration for request data
pub fn create_request_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_keypaths: vec![],
        commit_body_keypaths: vec![],
        reveal_key_commit_value_keypaths: vec![],
    }
}

/// Creates reveal configuration for response data
pub fn create_response_reveal_config() -> RevealConfig {
    use crate::BodyFieldConfig;

    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_keypaths: vec![BodyFieldConfig::Quoted(".username".into())],
        commit_body_keypaths: vec![BodyFieldConfig::UnquotedPadded(".balance".into(), 12)],
        reveal_key_commit_value_keypaths: vec![],
    }
}

/// Creates a test balance map for the server
pub fn create_test_balances() -> HashMap<String, u64> {
    let mut balances = HashMap::new();
    balances.insert("alice".to_string(), 100);
    balances
}

/// Verifies prover output contains expected commitments and secrets
pub fn verify_prover_output(prover_output: &ProverOutput) {
    assert!(
        !prover_output.transcript_commitments.is_empty(),
        "Prover should produce transcript commitments"
    );
    assert!(
        !prover_output.transcript_secrets.is_empty(),
        "Prover should produce transcript secrets"
    );
}

/// Verifies basic verifier output properties
pub fn verify_verifier_output_basic(verifier_output: &VerifierOutput) {
    assert_eq!(
        verifier_output.server_name, "localhost",
        "Verifier should verify correct server name"
    );

    let sent_data = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
        .expect("Sent data should be valid UTF-8");
    let received_data = String::from_utf8(verifier_output.transcript.received_unsafe().to_vec())
        .expect("Received data should be valid UTF-8");

    assert!(
        received_data.contains("username"),
        "Response should contain username field"
    );
    assert!(
        received_data.contains("alice"),
        "Response should contain alice username"
    );

    assert!(
        sent_data.contains("GET /api/balance/alice"),
        "Request should be a GET to /api/balance/alice"
    );
}

/// Verifies parsed request structure and content
pub fn verify_parsed_request(verifier_output: &VerifierOutput, sent_data: &str) {
    let parsed_request = verifier_output
        .parsed_request
        .as_ref()
        .expect("Request should be parsed");

    // Verify request line exists
    let request_line_range = parsed_request.method.start..parsed_request.protocol_version.end;
    let request_line_value = &sent_data[request_line_range.clone()];
    assert!(
        request_line_value.contains("GET /api/balance/alice HTTP/1.1"),
        "Request line should contain expected values"
    );

    // Verify request headers
    assert_eq!(parsed_request.headers.len(), 1);
    let content_type_headers = parsed_request
        .headers
        .get("content-type")
        .expect("Should have content-type header");

    let content_type = content_type_headers
        .first()
        .expect("Should have at least one content-type header");
    if let Some(value_range) = &content_type.value {
        let value = &sent_data[value_range.clone()];
        assert_eq!(value, "application/json");
    } else {
        panic!("content-type header should have a value");
    }
}

/// Verifies parsed response structure and content
pub fn verify_parsed_response(verifier_output: &VerifierOutput, received_data: &str) {
    let parsed_response = verifier_output
        .parsed_response
        .as_ref()
        .expect("Response should be parsed");

    // Verify status line exists
    let status_line_range = parsed_response.protocol_version.start..parsed_response.status.end;
    let status_line_value = &received_data[status_line_range.clone()];
    assert!(
        status_line_value.contains("HTTP/1.1 200 OK"),
        "Status line should contain expected values"
    );

    // Verify response body
    assert_eq!(
        parsed_response.body.len(),
        1,
        "Should have exactly one field"
    );
    let username_field = parsed_response
        .body
        .get(".username")
        .expect("Should have username field");

    match username_field {
        parser::redacted::Body::KeyValue { key: _, value } => {
            if let Some(value_range) = value {
                let username = &received_data[value_range.clone()];
                assert_eq!(username, "alice");
            } else {
                panic!("Username should have a value");
            }
        }
        parser::redacted::Body::Value(_) => {
            panic!("Username should be a key-value pair, not just a value");
        }
    }
}

#[cfg(test)]
mod integration {
    use futures::join;
    use server::{app::get_app, handle_connection};
    use shared::create_test_tls_config;

    use super::*;
    use crate::{HashAlgId, Prover, Verifier};

    #[test]
    fn test_end_to_end_proof_generation_and_verification() {
        shared::init_test_logging();

        smol::block_on(async {
            // Setup
            let test_tls_config = create_test_tls_config().unwrap();
            let sockets = create_test_sockets();

            let prover_config = create_prover_config(test_tls_config.cert_bytes.clone());
            let verifier_config = create_verifier_config(test_tls_config.cert_bytes);

            // Start server
            let app = get_app(create_test_balances());
            let server_task =
                handle_connection(app, test_tls_config.server_config, sockets.server_socket);

            // Build prover
            let prover = Prover::builder()
                .prover_config(prover_config)
                .request(create_test_request())
                .request_reveal_config(create_request_reveal_config())
                .response_reveal_config(create_response_reveal_config())
                .build()
                .unwrap();

            // Build verifier
            let verifier = Verifier::builder()
                .verifier_config(verifier_config)
                .build()
                .unwrap();

            // Execute protocol
            let prover_task =
                prover.prove(sockets.prover_verifier_socket, sockets.prover_server_socket);
            let verifier_task = verifier.verify(sockets.verifier_socket);

            let (server_result, prover_result, verifier_result) =
                join!(server_task, prover_task, verifier_task);

            // Verify all tasks completed successfully
            server_result.expect("Server should complete successfully");
            let prover_output = prover_result.expect("Prover should complete successfully");
            let verifier_output = verifier_result.expect("Verifier should complete successfully");

            // Verify prover output
            verify_prover_output(&prover_output);

            // Verify verifier output
            verify_verifier_output_basic(&verifier_output);

            // Verify parsed structures
            let sent_data = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
                .expect("Sent data should be valid UTF-8");
            let received_data =
                String::from_utf8(verifier_output.transcript.received_unsafe().to_vec())
                    .expect("Received data should be valid UTF-8");

            verify_parsed_request(&verifier_output, &sent_data);
            verify_parsed_response(&verifier_output, &received_data);
        });
    }

    #[test]
    fn test_prover_output_contains_commitments() {
        shared::init_test_logging();

        smol::block_on(async {
            let test_tls_config = create_test_tls_config().unwrap();
            let sockets = create_test_sockets();

            let prover_config = create_prover_config(test_tls_config.cert_bytes.clone());
            let verifier_config = create_verifier_config(test_tls_config.cert_bytes);

            let app = get_app(create_test_balances());
            let server_task =
                handle_connection(app, test_tls_config.server_config, sockets.server_socket);

            let prover = Prover::builder()
                .prover_config(prover_config)
                .request(create_test_request())
                .request_reveal_config(create_request_reveal_config())
                .response_reveal_config(create_response_reveal_config())
                .build()
                .unwrap();

            let verifier = Verifier::builder()
                .verifier_config(verifier_config)
                .build()
                .unwrap();

            let prover_task =
                prover.prove(sockets.prover_verifier_socket, sockets.prover_server_socket);
            let verifier_task = verifier.verify(sockets.verifier_socket);

            let (_, prover_result, _) = join!(server_task, prover_task, verifier_task);

            let prover_output = prover_result.expect("Prover should complete successfully");

            // Focused verification on prover output
            assert!(
                !prover_output.transcript_commitments.is_empty(),
                "Should have transcript commitments"
            );
            assert!(
                !prover_output.transcript_secrets.is_empty(),
                "Should have transcript secrets"
            );
        });
    }

    #[test]
    fn test_verifier_parses_request_correctly() {
        shared::init_test_logging();

        smol::block_on(async {
            let test_tls_config = create_test_tls_config().unwrap();
            let sockets = create_test_sockets();

            let prover_config = create_prover_config(test_tls_config.cert_bytes.clone());
            let verifier_config = create_verifier_config(test_tls_config.cert_bytes);

            let app = get_app(create_test_balances());
            let server_task =
                handle_connection(app, test_tls_config.server_config, sockets.server_socket);

            let prover = Prover::builder()
                .prover_config(prover_config)
                .request(create_test_request())
                .request_reveal_config(create_request_reveal_config())
                .response_reveal_config(create_response_reveal_config())
                .build()
                .unwrap();

            let verifier = Verifier::builder()
                .verifier_config(verifier_config)
                .build()
                .unwrap();

            let prover_task =
                prover.prove(sockets.prover_verifier_socket, sockets.prover_server_socket);
            let verifier_task = verifier.verify(sockets.verifier_socket);

            let (_, _, verifier_result) = join!(server_task, prover_task, verifier_task);

            let verifier_output = verifier_result.expect("Verifier should complete successfully");

            // Focused verification on parsed request
            let sent_data = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
                .expect("Sent data should be valid UTF-8");

            verify_parsed_request(&verifier_output, &sent_data);
        });
    }

    #[test]
    fn test_verifier_parses_response_correctly() {
        shared::init_test_logging();

        smol::block_on(async {
            let test_tls_config = create_test_tls_config().unwrap();
            let sockets = create_test_sockets();

            let prover_config = create_prover_config(test_tls_config.cert_bytes.clone());
            let verifier_config = create_verifier_config(test_tls_config.cert_bytes);

            let app = get_app(create_test_balances());
            let server_task =
                handle_connection(app, test_tls_config.server_config, sockets.server_socket);

            let prover = Prover::builder()
                .prover_config(prover_config)
                .request(create_test_request())
                .request_reveal_config(create_request_reveal_config())
                .response_reveal_config(create_response_reveal_config())
                .build()
                .unwrap();

            let verifier = Verifier::builder()
                .verifier_config(verifier_config)
                .build()
                .unwrap();

            let prover_task =
                prover.prove(sockets.prover_verifier_socket, sockets.prover_server_socket);
            let verifier_task = verifier.verify(sockets.verifier_socket);

            let (_, _, verifier_result) = join!(server_task, prover_task, verifier_task);

            let verifier_output = verifier_result.expect("Verifier should complete successfully");

            // Focused verification on parsed response
            let received_data =
                String::from_utf8(verifier_output.transcript.received_unsafe().to_vec())
                    .expect("Received data should be valid UTF-8");

            verify_parsed_response(&verifier_output, &received_data);
        });
    }

    #[test]
    fn test_validator() {
        shared::init_test_logging();

        smol::block_on(async {
            let test_tls_config = create_test_tls_config().unwrap();
            let sockets = create_test_sockets();

            let prover_config = create_prover_config(test_tls_config.cert_bytes.clone());
            let verifier_config = create_verifier_config(test_tls_config.cert_bytes);

            let mut balances = HashMap::new();
            balances.insert("alice".to_string(), 100);
            let app = get_app(balances);
            let server_task =
                handle_connection(app, test_tls_config.server_config, sockets.server_socket);

            let prover = Prover::builder()
                .prover_config(prover_config)
                .request(create_test_request())
                .request_reveal_config(create_request_reveal_config())
                .response_reveal_config(create_response_reveal_config())
                .build()
                .unwrap();

            let verifier = Verifier::builder()
                .verifier_config(verifier_config)
                .build()
                .unwrap();

            let prover_task =
                prover.prove(sockets.prover_verifier_socket, sockets.prover_server_socket);
            let verifier_task = verifier.verify(sockets.verifier_socket);

            let (_, _, verifier_result) = join!(server_task, prover_task, verifier_task);

            let verifier_output = verifier_result.expect("Verifier should complete successfully");

            // Test validator with expected properties
            let validator = Validator::builder()
                .expected_server_name("localhost")
                .expected_hash_alg(HashAlgId::BLAKE3)
                .request_header_equals("content-type", "application/json")
                .response_body_field_equals(".username", ExpectedValue::String("alice".to_string()))
                .build();

            validator
                .validate(&verifier_output)
                .expect("Validation should pass with correct properties");

            // Test validator with wrong server name
            let wrong_validator = Validator::builder()
                .expected_server_name("wronghost")
                .build();

            assert!(
                wrong_validator.validate(&verifier_output).is_err(),
                "Validation should fail with wrong server name"
            );

            // Test validator with wrong header value
            let wrong_header_validator = Validator::builder()
                .request_header_equals("content-type", "text/html")
                .build();

            assert!(
                wrong_header_validator.validate(&verifier_output).is_err(),
                "Validation should fail with wrong header value"
            );

            // Test validator with wrong body field value
            let wrong_body_validator = Validator::builder()
                .response_body_field_equals(".username", ExpectedValue::String("bob".to_string()))
                .build();

            assert!(
                wrong_body_validator.validate(&verifier_output).is_err(),
                "Validation should fail with wrong body field value"
            );
        });
    }
}
