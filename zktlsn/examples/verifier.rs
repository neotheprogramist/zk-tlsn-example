use tlsnotary::Verifier;
use zktlsn::{
    receive_proof_message,
    tests::{
        create_verifier_config, verify_balance_commitment_and_proof, verify_parsed_request,
        verify_parsed_response, verify_verifier_output_basic,
    },
};

fn main() {
    shared::init_test_logging();

    smol::block_on(async {
        use std::path::Path;

        use smol::net::TcpListener;

        let cert_path = Path::new("test_cert.pem");
        let key_path = Path::new("test_key.pem");

        let test_tls_config = shared::get_or_create_test_tls_config(cert_path, key_path).unwrap();
        let verifier_config = create_verifier_config(test_tls_config.cert_bytes);

        let listener = TcpListener::bind("127.0.0.1:7000")
            .await
            .expect("Failed to bind to port 7000");

        tracing::info!("Verifier listening on 127.0.0.1:7000 for MPC-TLS");
        tracing::info!("Waiting for prover connection...");

        let (verifier_socket, addr) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        tracing::info!("Accepted MPC-TLS connection from prover at {}", addr);

        let verifier = Verifier::builder()
            .verifier_config(verifier_config)
            .build()
            .unwrap();

        tracing::info!("Starting verification protocol...");

        let verifier_output = verifier
            .verify(verifier_socket)
            .await
            .expect("Verifier should complete successfully");

        verify_verifier_output_basic(&verifier_output);

        let sent_data = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
            .expect("Sent data should be valid UTF-8");
        let received_data =
            String::from_utf8(verifier_output.transcript.received_unsafe().to_vec())
                .expect("Received data should be valid UTF-8");

        verify_parsed_request(&verifier_output, &sent_data);
        verify_parsed_response(&verifier_output, &received_data);

        tracing::info!("Verifier completed successfully");
        tracing::info!("Server name: {}", verifier_output.server_name);
        tracing::info!("Sent data length: {} bytes", sent_data.len());
        tracing::info!("Received data length: {} bytes", received_data.len());

        tracing::info!("Waiting for ZK proof from prover...");

        // Listen for proof on a separate port
        // Note: This is a second TCP connection, following the TLSN interactive_zk pattern
        let proof_listener = TcpListener::bind("127.0.0.1:7001")
            .await
            .expect("Failed to bind to port 7001 for proof reception");

        tracing::info!("Listening on 127.0.0.1:7001 for proof transmission");

        let (mut proof_socket, proof_addr) = proof_listener
            .accept()
            .await
            .expect("Failed to accept proof connection");
        tracing::info!("Accepted proof connection from {}", proof_addr);

        // Receive proof from prover
        let proof_message = receive_proof_message(&mut proof_socket)
            .await
            .expect("Failed to receive proof from prover");

        tracing::info!(
            session_id = ?proof_message.session_id,
            commitment_count = proof_message.metadata.commitment_count,
            timestamp = proof_message.metadata.timestamp,
            description = ?proof_message.metadata.description,
            "Received proof from prover"
        );

        tracing::info!("Verifying balance commitment and ZK proof...");

        // Verify the ZK proof against the verifier output
        verify_balance_commitment_and_proof(&verifier_output, &proof_message.proof)
            .expect("Balance commitment and proof verification should succeed");

        tracing::info!(
            session_id = ?proof_message.session_id,
            "ZK proof verification successful!"
        );
    });
}
