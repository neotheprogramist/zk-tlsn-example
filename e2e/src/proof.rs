use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result, ensure};
use async_compat::Compat;
use async_compat::Compat as CompatStream;
use futures::AsyncWriteExt;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use tlsnotary::{
    HashAlgId, ProveConfig, ProverConfig, Session, Transcript, TranscriptCommitConfig,
    TranscriptCommitment, TranscriptCommitmentKind, TranscriptSecret,
    prover::{reveal_request, reveal_response},
};
use tokio::net::TcpStream;
use tracing::info;

use crate::verifier::VerificationOutcome;

use crate::demo::{
    create_prover_config, create_request_reveal_config, create_response_reveal_config,
    create_tlsn_request,
};

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
    let session = Session::new(Compat::new(stream));
    let (driver, mut handle) = session.split();
    let driver_task = smol::spawn(driver);

    let cert_bytes = crate::testing::load_test_cert_bytes(server_cert_path)
        .context("failed to load TLS server certificate")?;
    let (tls_client_config, tls_commit_config) = create_prover_config(cert_bytes, server_name)
        .context("failed to create prover TLS configuration")?;

    let prover = handle
        .new_prover(
            ProverConfig::builder()
                .build()
                .context("failed to build prover config")?,
        )?
        .commit(tls_commit_config)
        .await
        .context("failed to commit prover configuration")?;

    let prover_server_socket = CompatStream::new(
        TcpStream::connect(server_addr)
            .await
            .with_context(|| format!("failed to connect to {server_addr}"))?,
    );
    let (tls_connection, prover_fut) = prover
        .connect(tls_client_config, prover_server_socket)
        .await
        .context("failed to establish MPC-TLS connection")?;
    let tls_connection = TokioIo::new(Compat::new(tls_connection));
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .context("failed to create HTTP/1 client over MPC-TLS")?;

    let request_task = async move {
        let response = request_sender
            .send_request(
                create_tlsn_request(tx_id).context("failed to build attestation request")?,
            )
            .await
            .context("failed to send attestation request")?;
        ensure!(
            response.status() == StatusCode::OK,
            "unexpected backend status: {}",
            response.status()
        );
        response
            .collect()
            .await
            .context("failed to collect attestation response body")
            .map(|collected| collected.to_bytes())
    };

    let (prover_result, connection_result, response_result) =
        futures::join!(prover_fut, connection, request_task);
    let mut prover = prover_result.context("TLSNotary prover future failed")?;
    connection_result.context("HTTP connection task failed")?;
    let _response_body = response_result?;

    let transcript = prover.transcript().clone();
    let request_text = String::from_utf8(transcript.sent().to_vec())
        .context("failed to decode prover request transcript as UTF-8")?;
    let response_text = String::from_utf8(transcript.received().to_vec())
        .context("failed to decode prover response transcript as UTF-8")?;
    let received_transcript = transcript.received().to_vec();
    info!(
        request_len = request_text.len(),
        response_len = response_text.len(),
        "Prover finished MPC-TLS, obtained raw request/response bytes"
    );
    info!("Prover raw request bytes (on the wire):\n{request_text}");
    info!("Prover raw response bytes (on the wire):\n{response_text}");
    let prove_config = build_prove_config(&transcript)?;

    let prover_output = prover
        .prove(&prove_config)
        .await
        .context("failed to generate TLSNotary proof")?;
    prover.close().await.context("failed to close prover")?;
    handle.close();
    let mut verifier_stream = driver_task.await.context("TLSNotary driver failed")?;

    let verification = VerificationOutcome::read_from(&mut verifier_stream)
        .await
        .context("failed to read verification outcome")?;
    verifier_stream
        .close()
        .await
        .context("failed to close verifier stream")?;

    Ok(NotarizedFlow {
        verification,
        request_text,
        response_text,
        commitment_count: prover_output.transcript_commitments.len(),
        transcript_commitments: prover_output.transcript_commitments,
        transcript_secrets: prover_output.transcript_secrets,
        received_transcript,
    })
}

fn build_prove_config(transcript: &Transcript) -> Result<ProveConfig> {
    let mut prove_config_builder = ProveConfig::builder(transcript);
    prove_config_builder.server_identity();

    let mut transcript_commit_builder = TranscriptCommitConfig::builder(transcript);
    transcript_commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::BLAKE3,
    });

    reveal_request(
        transcript.sent(),
        &mut prove_config_builder,
        &mut transcript_commit_builder,
        &create_request_reveal_config(),
    )
    .context("failed to configure request transcript reveal")?;
    reveal_response(
        transcript.received(),
        &mut prove_config_builder,
        &mut transcript_commit_builder,
        &create_response_reveal_config(),
    )
    .context("failed to configure response transcript reveal")?;

    prove_config_builder.transcript_commit(
        transcript_commit_builder
            .build()
            .context("failed to build transcript commit config")?,
    );
    prove_config_builder
        .build()
        .context("failed to build proof config")
}
