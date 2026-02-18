use std::{net::SocketAddr, path::Path};

use async_compat::Compat;
use axum::body::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{StatusCode, Uri};
use hyper_util::rt::TokioIo;
use quinn::Endpoint;
use serde::{Deserialize, Serialize};
use shared::{
    TestQuicConfig, TestTlsConfig, get_or_create_test_quic_config, get_or_create_test_tls_config,
};
use smol::net::TcpStream;
use tlsnotary::{
    CertificateDer, MpcTlsConfig, Prover, RootCertStore, ServerName, TlsClientConfig,
    TlsCommitConfig,
};
use tokio::io::{AsyncRead, AsyncWrite, join};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use zktlsn::{PaddingConfig, Proof, generate_proof};

/// Maximum sent data size (4 KB)
const MAX_SENT_DATA: usize = 1 << 12;
/// Maximum received data size (16 KB)
const MAX_RECV_DATA: usize = 1 << 14;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    session_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationRequest {
    session_id: String,
    proof: Proof,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationResponse {
    success: bool,
    server_name: String,
    verified_fields: Vec<String>,
    message: Option<String>,
}

fn main() {
    // Setup Barretenberg SRS (required before proof generation)
    zktlsn::setup_barretenberg_srs().expect("Failed to setup Barretenberg SRS");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
        .with_test_writer()
        .try_init()
        .unwrap();

    smol::block_on(async {
        // Setup QUIC client for connecting to verifier
        let TestQuicConfig { client_config, .. } =
            get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await;
        let addr: SocketAddr = "[::]:0".parse().unwrap();

        let mut endpoint = Endpoint::client(addr).unwrap();
        endpoint.set_default_client_config(client_config);

        let server_addr: SocketAddr = "[::1]:5000".parse().unwrap();
        let conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .expect("Failed to connect to verifier");

        tracing::info!("Connected to verifier at {}", server_addr);

        // Step 1: Call /session to get a session_id
        let (send, recv) = conn.open_bi().await.unwrap();
        let stream = join(recv, send);

        let uri = Uri::from_static("/session");
        let (status_code, response_bytes) = send_post_request(stream, uri, Bytes::new()).await;

        assert_eq!(
            status_code,
            StatusCode::OK,
            "Session request should succeed"
        );

        let session_response: SessionResponse =
            serde_json::from_slice(&response_bytes).expect("Failed to parse session response");
        let session_id = session_response.session_id;

        tracing::info!(session_id = %session_id, "Got session ID from verifier");

        // Step 2: Call /notarize with upgrade to get raw stream for MPC-TLS
        let (send, recv) = conn.open_bi().await.unwrap();
        let stream = join(recv, send);

        let notarize_uri: Uri = format!("/notarize?sessionId={}", session_id)
            .parse()
            .expect("Valid URI");

        tracing::info!("Requesting notarization with upgrade...");

        let verifier_stream = send_upgrade_request(stream, notarize_uri).await;

        tracing::info!("Got upgraded stream from verifier");

        // Step 3: Connect to TLS server
        let prover_server_socket = TcpStream::connect("localhost:8443")
            .await
            .expect("Failed to connect to TLS server");

        tracing::info!("Connected to TLS server at localhost:8443");

        // Step 4: Setup prover configuration
        let TestTlsConfig { cert_bytes, .. } =
            get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))
                .unwrap();

        let (tls_client_config, tls_commit_config) = create_prover_config(cert_bytes);

        // Step 5: Build and run prover
        let prover = Prover::builder()
            .tls_client_config(tls_client_config)
            .tls_commit_config(tls_commit_config)
            .request(create_test_request())
            .request_reveal_config(create_request_reveal_config())
            .response_reveal_config(create_response_reveal_config())
            .build()
            .unwrap();

        tracing::info!("Starting MPC-TLS proving protocol...");

        let prover_output = prover
            .prove(Compat::new(verifier_stream), prover_server_socket)
            .await
            .expect("Prover should complete successfully");

        tracing::info!("Prover completed successfully");
        tracing::info!(
            "Generated {} transcript commitments",
            prover_output.transcript_commitments.len()
        );
        tracing::info!(
            "Generated {} transcript secrets",
            prover_output.transcript_secrets.len()
        );

        // Verify output
        assert!(
            !prover_output.transcript_commitments.is_empty(),
            "Prover should produce transcript commitments"
        );
        assert!(
            !prover_output.transcript_secrets.is_empty(),
            "Prover should produce transcript secrets"
        );

        tracing::info!("Notarization completed, generating ZK proof...");

        // Step 6: Generate ZK proof from the prover output
        // The padding config must match what was used in the reveal config (12 bytes for balance)
        let padding_config = PaddingConfig::new(12);
        let proof = generate_proof(
            &prover_output.transcript_commitments,
            &prover_output.transcript_secrets,
            &prover_output.received,
            padding_config,
        )
        .expect("Failed to generate ZK proof");

        tracing::info!(
            "ZK proof generated: {} bytes proof, {} bytes verification key",
            proof.proof.len(),
            proof.verification_key.len()
        );

        // Step 7: Call /verify endpoint to verify the ZK proof
        tracing::info!("Sending ZK proof to verifier for verification...");

        let (send, recv) = conn.open_bi().await.unwrap();
        let stream = join(recv, send);

        let verify_request = VerificationRequest {
            session_id: session_id.clone(),
            proof,
        };
        let verify_body =
            Bytes::from(serde_json::to_vec(&verify_request).expect("Failed to serialize request"));

        let verify_uri = Uri::from_static("/verify");
        let (status_code, response_bytes) =
            send_post_request(stream, verify_uri, verify_body).await;

        if status_code == StatusCode::OK {
            let verify_response: VerificationResponse = serde_json::from_slice(&response_bytes)
                .expect("Failed to parse verification response");

            assert!(verify_response.success, "Verification should succeed");
            tracing::info!(
                "Verification successful! Server: {}, Fields: {:?}",
                verify_response.server_name,
                verify_response.verified_fields
            );
            if let Some(message) = verify_response.message {
                tracing::info!("Message: {}", message);
            }
        } else {
            let error_message = String::from_utf8_lossy(&response_bytes);
            tracing::error!(
                "Verification failed with status {}: {}",
                status_code,
                error_message
            );
            panic!("Verification failed");
        }

        tracing::info!("Full ZK-TLS notarization and verification flow completed successfully!");
    });
}

/// Creates prover TLS and commit configurations with test settings
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

/// Creates a test HTTP request for balance API endpoint
fn create_test_request() -> hyper::Request<Empty<Bytes>> {
    hyper::Request::builder()
        .method("GET")
        .uri("/api/balance/alice")
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .expect("Failed to build request")
}

/// Creates reveal configuration for request data
fn create_request_reveal_config() -> tlsnotary::prover::RevealConfig {
    tlsnotary::prover::RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_keypaths: vec![],
        commit_body_keypaths: vec![],
        reveal_key_commit_value_keypaths: vec![],
    }
}

/// Creates reveal configuration for response data
fn create_response_reveal_config() -> tlsnotary::prover::RevealConfig {
    use tlsnotary::{BodyFieldConfig, KeyValueCommitConfig};

    tlsnotary::prover::RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_keypaths: vec![BodyFieldConfig::Quoted(".username".into())],
        commit_body_keypaths: vec![],
        reveal_key_commit_value_keypaths: vec![KeyValueCommitConfig::with_padding(
            ".balance".into(),
            12,
        )],
    }
}

/// Send a POST request using HTTP/1.1 and return the response
async fn send_post_request<IO>(stream: IO, uri: Uri, body: Bytes) -> (StatusCode, Vec<u8>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await.unwrap();

    let request_task = async move {
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(body))
            .expect("valid request");

        let res = sender.send_request(req).await.unwrap();

        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();

        (status, body)
    };

    let (conn_result, response) = futures::join!(conn, request_task);
    conn_result.unwrap();
    response
}

/// Send an upgrade request and return the upgraded stream
async fn send_upgrade_request<IO>(stream: IO, uri: Uri) -> TokioIo<hyper::upgrade::Upgraded>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await.unwrap();

    // Spawn connection handler
    smol::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::error!("Connection error: {:?}", e);
        }
    })
    .detach();

    let req = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Connection", "Upgrade")
        .header("Upgrade", "tcp")
        .body(Empty::<Bytes>::new())
        .expect("valid request");

    let res = sender.send_request(req).await.unwrap();

    tracing::info!("Upgrade response status: {}", res.status());

    // Get the upgraded connection
    let upgraded = hyper::upgrade::on(res)
        .await
        .expect("Failed to upgrade connection");

    TokioIo::new(upgraded)
}
