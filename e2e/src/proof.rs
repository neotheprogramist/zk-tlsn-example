use std::{net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result};
use async_compat::Compat;
use futures::AsyncWriteExt;
use tlsnotary::{SmolRuntime, TranscriptCommitment, TranscriptSecret};
use tokio::net::TcpStream;
use tracing::info;

use crate::demo::{
    create_prover_config, create_request_reveal_config, create_response_reveal_config,
    create_tlsn_request,
};
use crate::verifier::VerificationOutcome;

pub struct NotarizedFlow {
    pub verification: VerificationOutcome,
    pub request_text: String,
    pub response_text: String,
    pub commitment_count: usize,
    pub transcript_commitments: Vec<TranscriptCommitment>,
    pub transcript_secrets: Vec<TranscriptSecret>,
    pub received_transcript: Vec<u8>,
}

pub async fn run_attest_only_flow<IO>(
    stream: IO,
    server_addr: SocketAddr,
    server_name: &str,
    server_cert_path: &Path,
    tx_id: u64,
) -> Result<NotarizedFlow>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let cert_bytes = crate::tls::load_test_cert_bytes(server_cert_path)
        .context("failed to load TLS server certificate")?;
    let (tls_client_config, tls_commit_config) = create_prover_config(cert_bytes, server_name)
        .context("failed to create prover TLS configuration")?;

    let prover = tlsnotary::Prover::builder(
        Arc::new(SmolRuntime),
        tls_client_config,
        tls_commit_config,
        create_tlsn_request(tx_id).context("failed to build attestation request")?,
    )
    .request_reveal_config(create_request_reveal_config())
    .response_reveal_config(create_response_reveal_config())
    .build();

    let verifier_io = Compat::new(stream);
    let server_io = Compat::new(
        TcpStream::connect(server_addr)
            .await
            .with_context(|| format!("failed to connect to {server_addr}"))?,
    );

    let (mut verifier_io, output) = prover
        .prove(verifier_io, server_io)
        .await
        .context("TLSNotary prover failed")?;

    let request_text = String::from_utf8(output.sent.clone())
        .context("failed to decode prover request transcript as UTF-8")?;
    let response_text = String::from_utf8(output.received.clone())
        .context("failed to decode prover response transcript as UTF-8")?;
    info!(
        request_len = request_text.len(),
        response_len = response_text.len(),
        "Prover finished MPC-TLS, obtained raw request/response bytes"
    );
    info!("Prover raw request bytes (on the wire):\n{request_text}");
    info!("Prover raw response bytes (on the wire):\n{response_text}");

    let verification = VerificationOutcome::read_from(&mut verifier_io)
        .await
        .context("failed to read verification outcome")?;
    verifier_io
        .close()
        .await
        .context("failed to close verifier stream")?;

    Ok(NotarizedFlow {
        verification,
        request_text,
        response_text,
        commitment_count: output.transcript_commitments.len(),
        transcript_commitments: output.transcript_commitments,
        transcript_secrets: output.transcript_secrets,
        received_transcript: output.received,
    })
}
