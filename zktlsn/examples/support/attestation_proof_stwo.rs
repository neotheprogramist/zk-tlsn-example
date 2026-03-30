use std::net::SocketAddr;

use anyhow::{Context, Result, ensure};
use async_compat::Compat;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use smol::net::TcpStream;
use tlsnotary::{
    HashAlgId, ProveConfig, ProverConfig, Session, TranscriptCommitConfig,
    TranscriptCommitmentKind,
    prover::{reveal_request, reveal_response},
};
use zktlsn::{NoirProverInputs, PaddingConfig, derive_noir_prover_inputs};

use crate::live_demo::{
    create_prover_config, create_request_reveal_config, create_response_reveal_config,
    create_tlsn_request, load_tls_materials,
};

pub async fn derive_stwo_inputs_from_tlsn<IO>(
    stream: IO,
    server_addr: SocketAddr,
    server_name: &str,
    tx_id: u64,
) -> Result<NoirProverInputs>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(Compat::new(stream));
    let (driver, mut handle) = session.split();
    let driver_task = smol::spawn(driver);

    let tls_materials = load_tls_materials()?;
    let (tls_client_config, tls_commit_config) =
        create_prover_config(tls_materials.cert_bytes, server_name)
            .context("failed to create prover TLS configuration")?;

    let prover = handle
        .new_prover(
            ProverConfig::builder()
                .build()
                .map_err(tlsnotary::Error::from)
                .context("failed to build prover config")?,
        )?
        .commit(tls_commit_config)
        .await
        .context("failed to commit prover configuration")?;

    let prover_server_socket = TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("failed to connect to {server_addr}"))?;
    let (tls_connection, prover_fut) = prover
        .connect(tls_client_config, prover_server_socket)
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
    let received_transcript = transcript.received().to_vec();
    let mut prove_config_builder = ProveConfig::builder(&transcript);
    prove_config_builder.server_identity();

    let mut transcript_commit_builder = TranscriptCommitConfig::builder(&transcript);
    transcript_commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::BLAKE2S,
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
            .map_err(tlsnotary::Error::from)
            .context("failed to build transcript commit config")?,
    );
    let prove_config = prove_config_builder
        .build()
        .map_err(tlsnotary::Error::from)
        .context("failed to build proof config")?;

    let prover_output = prover
        .prove(&prove_config)
        .await
        .context("failed to generate TLSNotary proof")?;
    prover.close().await.context("failed to close prover")?;
    handle.close();
    let _ = driver_task.await.context("TLSNotary driver failed")?;

    derive_noir_prover_inputs(
        &prover_output.transcript_commitments,
        &prover_output.transcript_secrets,
        &received_transcript,
        PaddingConfig::new(shared::ATTESTATION_LEN),
    )
    .context("failed to derive proof inputs from TLS transcript")
}
