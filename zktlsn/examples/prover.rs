use tlsnotary::Prover;
use zktlsn::{
    PaddingConfig, ProofMessage, generate_proof, generate_session_id, send_proof_message,
    tests::{
        create_prover_config, create_request_reveal_config, create_response_reveal_config,
        create_test_request, verify_prover_output,
    },
};

fn main() {
    shared::init_test_logging();

    smol::block_on(async {
        use std::path::Path;

        use smol::net::TcpStream;

        let cert_path = Path::new("test_cert.pem");
        let key_path = Path::new("test_key.pem");

        let test_tls_config = shared::get_or_create_test_tls_config(cert_path, key_path).unwrap();
        let prover_config = create_prover_config(test_tls_config.cert_bytes.clone());

        // Generate a unique session ID for this proof session
        let session_id = generate_session_id();
        tracing::info!(?session_id, "Generated session ID");

        tracing::info!("Prover starting...");
        tracing::info!("Connecting to verifier at 127.0.0.1:7000 for MPC-TLS...");

        let prover_verifier_socket = TcpStream::connect("127.0.0.1:7000")
            .await
            .expect("Failed to connect to verifier");

        tracing::info!("Connected to verifier for MPC-TLS");
        tracing::info!("Connecting to server at 127.0.0.1:8443...");

        let prover_server_socket = TcpStream::connect("127.0.0.1:8443")
            .await
            .expect("Failed to connect to server");

        tracing::info!("Connected to server");

        let prover = Prover::builder()
            .prover_config(prover_config)
            .request(create_test_request())
            .request_reveal_config(create_request_reveal_config())
            .response_reveal_config(create_response_reveal_config())
            .build()
            .unwrap();

        tracing::info!("Starting proving protocol...");

        let prover_output = prover
            .prove(prover_verifier_socket, prover_server_socket)
            .await
            .expect("Prover should complete successfully");

        verify_prover_output(&prover_output);

        tracing::info!("Prover completed successfully");
        tracing::info!(
            "Generated {} transcript commitments",
            prover_output.transcript_commitments.len()
        );
        tracing::info!(
            "Generated {} transcript secrets",
            prover_output.transcript_secrets.len()
        );

        tracing::info!("Generating ZK proof...");
        let padding_config = PaddingConfig::new(12);
        let proof = generate_proof(
            &prover_output.transcript_commitments,
            &prover_output.transcript_secrets,
            &prover_output.received,
            padding_config,
        )
        .expect("Proof generation should succeed");

        tracing::info!("ZK proof generated successfully");

        // Create proof message with metadata
        let proof_message = ProofMessage::with_description(
            session_id,
            proof,
            prover_output.transcript_commitments.len(),
            "Balance commitment proof".to_string(),
        );

        tracing::info!(
            session_id = ?session_id,
            commitment_count = proof_message.metadata.commitment_count,
            "Sending proof to verifier..."
        );

        // Connect to verifier's proof reception port
        // Note: This is a second TCP connection, as the MPC-TLS socket was consumed by prove()
        tracing::info!("Connecting to verifier at 127.0.0.1:7001 for proof transmission...");
        let mut proof_socket = TcpStream::connect("127.0.0.1:7001")
            .await
            .expect("Failed to connect to verifier for proof transmission");

        // Send proof to verifier
        send_proof_message(&mut proof_socket, &proof_message)
            .await
            .expect("Failed to send proof to verifier");

        tracing::info!("Proof sent to verifier successfully");
    });
}
