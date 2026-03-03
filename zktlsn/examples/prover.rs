use std::{io::Error as IoError, net::SocketAddr, path::Path};

use async_compat::Compat;
use futures::AsyncWriteExt;
use http_body_util::{BodyExt, Empty};
use hyper::{StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use quinn::Endpoint;
use shared::{
    TestQuicConfig, TestTlsConfig, get_or_create_test_quic_config, get_or_create_test_tls_config,
    init_logging,
};
use smol::net::TcpStream;
use tlsnotary::{
    CertificateDer, HashAlgId, MpcTlsConfig, ProveConfig, ProverConfig, RootCertStore, ServerName,
    Session, TlsClientConfig, TlsCommitConfig, TranscriptCommitConfig, TranscriptCommitmentKind,
    prover::{RevealConfig, reveal_request, reveal_response},
};
use tracing::{error, info, instrument};
use verifier::{ProofMessage, VerificationOutcome};
use zktlsn::{PaddingConfig, generate_proof};

/// Maximum sent data size (4 KB)
const MAX_SENT_DATA: usize = 1 << 12;
/// Maximum received data size (16 KB)
const MAX_RECV_DATA: usize = 1 << 14;

type ExampleResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct StepProgress {
    current: usize,
    total: usize,
}

impl StepProgress {
    fn new(total: usize) -> Self {
        Self { current: 0, total }
    }

    fn tick(&mut self, stage: &str) {
        self.current = (self.current + 1).min(self.total);
        let width = 24usize;
        let filled = (self.current * width) / self.total.max(1);
        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            "░".repeat(width.saturating_sub(filled))
        );
        let percent = (self.current * 100) / self.total.max(1);
        info!(
            stage = %stage,
            step = self.current,
            total_steps = self.total,
            percent,
            progress_bar = %bar,
            "Prover progress"
        );
    }
}

fn main() {
    init_logging("info");

    smol::block_on(async {
        if let Err(err) = run().await {
            error!(error = %err, "Prover flow failed");
            std::process::exit(1);
        }
    });
}

#[instrument]
async fn run() -> ExampleResult<()> {
    let mut progress = StepProgress::new(5);
    progress.tick("prepare QUIC client configuration");
    let TestQuicConfig { client_config, .. } =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await?;
    let client_addr: SocketAddr = "[::]:0".parse()?;

    let mut endpoint = Endpoint::client(client_addr)?;
    endpoint.set_default_client_config(client_config);

    let verifier_addr: SocketAddr = "[::1]:5000".parse()?;
    let connection = endpoint.connect(verifier_addr, "localhost")?.await?;
    info!(%verifier_addr, "Connected to verifier");
    progress.tick("connected to verifier");

    let (send, recv) = connection.open_bi().await?;
    let stream = tokio::io::join(recv, send);
    progress.tick("opened QUIC bidirectional stream");
    let verification_result = run_single_stream_prover_flow(stream).await?;
    progress.tick("received verification result");

    if !verification_result.success {
        return Err(IoError::other(format!(
            "verification failed: {}",
            verification_result.message
        ))
        .into());
    }

    info!(
        server_name = %verification_result.server_name,
        verified_fields = ?verification_result.verified_fields,
        "Full ZK-TLS notarization and verification flow completed successfully"
    );
    progress.tick("flow complete");
    Ok(())
}

#[instrument(skip(stream), fields(phase = "notarize+prove+verify"))]
async fn run_single_stream_prover_flow<IO>(stream: IO) -> ExampleResult<VerificationOutcome>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut progress = StepProgress::new(8);
    let session = Session::new(Compat::new(stream));
    let (driver, mut handle) = session.split();
    let driver_task = smol::spawn(driver);
    progress.tick("created TLSN session");

    let TestTlsConfig { cert_bytes, .. } =
        get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))?;
    let (tls_client_config, tls_commit_config) = create_prover_config(cert_bytes)?;
    progress.tick("prepared TLS client/commit configuration");

    let prover = handle
        .new_prover(
            ProverConfig::builder()
                .build()
                .map_err(tlsnotary::Error::from)?,
        )?
        .commit(tls_commit_config)
        .await?;
    progress.tick("committed TLSN prover configuration");

    let prover_server_socket = TcpStream::connect("localhost:8443").await?;
    info!("Connected to TLS server at localhost:8443");
    progress.tick("connected to backend TLS server");

    let (tls_connection, prover_fut) = prover
        .connect(tls_client_config, prover_server_socket)
        .await?;
    let tls_connection = TokioIo::new(Compat::new(tls_connection));

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    let request_task = async move {
        let response = request_sender.send_request(create_test_request()?).await?;
        if response.status() != StatusCode::OK {
            return Err(IoError::other(format!(
                "unexpected backend status: {}",
                response.status()
            ))
            .into());
        }

        let response_body = response.collect().await?.to_bytes().to_vec();
        Ok::<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>(response_body)
    };

    let (prover_result, connection_result, response_result) =
        futures::join!(prover_fut, connection, request_task);
    let mut prover = prover_result?;
    connection_result?;
    response_result?;
    progress.tick("completed backend HTTP exchange");

    let transcript = prover.transcript().clone();
    let received_transcript = transcript.received().to_vec();
    info!(
        "Prover full request view (fully revealed baseline):\n{}",
        render_full_transcript_view(transcript.sent())
    );
    info!(
        "Prover full response view (fully revealed baseline):\n{}",
        render_full_transcript_view(transcript.received())
    );

    let mut prove_config_builder = ProveConfig::builder(&transcript);
    prove_config_builder.server_identity();

    let mut transcript_commit_builder = TranscriptCommitConfig::builder(&transcript);
    transcript_commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::BLAKE3,
    });

    let request_reveal = create_request_reveal_config();
    let response_reveal = create_response_reveal_config();

    reveal_request(
        transcript.sent(),
        &mut prove_config_builder,
        &mut transcript_commit_builder,
        &request_reveal,
    )?;
    reveal_response(
        transcript.received(),
        &mut prove_config_builder,
        &mut transcript_commit_builder,
        &response_reveal,
    )?;

    prove_config_builder.transcript_commit(
        transcript_commit_builder
            .build()
            .map_err(tlsnotary::Error::from)?,
    );
    let prove_config = prove_config_builder
        .build()
        .map_err(tlsnotary::Error::from)?;

    let prover_output = prover.prove(&prove_config).await?;
    prover.close().await?;
    handle.close();
    let mut stream = driver_task.await?;
    progress.tick("generated TLSN commitments and secrets");

    info!(
        commitments = prover_output.transcript_commitments.len(),
        secrets = prover_output.transcript_secrets.len(),
        "TLSNotary proving complete"
    );

    let proof = generate_proof(
        &prover_output.transcript_commitments,
        &prover_output.transcript_secrets,
        &received_transcript,
        PaddingConfig::new(12),
    )?;
    let proof_bytes = serde_json::to_vec(&proof)?;
    info!(
        serialized_proof_len = proof_bytes.len(),
        "Generated ZK proof"
    );
    progress.tick("generated ZK proof");

    ProofMessage::new(proof).write_to(&mut stream).await?;
    let verification_result = VerificationOutcome::read_from(&mut stream).await?;
    stream.close().await?;
    progress.tick("submitted proof and read verifier response");

    Ok(verification_result)
}

fn create_prover_config(
    cert_bytes: Vec<u8>,
) -> tlsnotary::Result<(TlsClientConfig, TlsCommitConfig)> {
    let server_name = ServerName::Dns("localhost".to_string().try_into().map_err(|error| {
        tlsnotary::Error::InvalidInput(format!("invalid DNS server name 'localhost': {error}"))
    })?);

    let tls_client_config = TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()?;

    let tls_commit_config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .build()?;

    Ok((tls_client_config, tls_commit_config))
}

fn create_test_request() -> Result<hyper::Request<Empty<Bytes>>, hyper::http::Error> {
    hyper::Request::builder()
        .method("GET")
        .uri("/api/balance/alice")
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
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
    use tlsnotary::{BodyFieldConfig, KeyValueCommitConfig};

    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_fields: vec![BodyFieldConfig::Quoted(".username".into())],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![KeyValueCommitConfig::with_padding(".balance".into(), 12)],
    }
}

fn render_full_transcript_view(bytes: &[u8]) -> String {
    let mut out = String::new();

    for byte in bytes {
        match *byte {
            b'\r' | b'\n' => {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            b'\t' => out.push('\t'),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push_str(&format!("\\x{byte:02X}")),
        }
    }

    out
}
