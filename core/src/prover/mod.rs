mod reveal;

use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite, channel::oneshot, join};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
pub use reveal::{BodyFieldConfig, KeyValueCommitConfig, RevealConfig};
use reveal::{reveal_request, reveal_response};
use tlsn::{
    Session, SessionHandle,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::TlsCommitConfig,
    },
    hash::HashAlgId,
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
};

use crate::{
    Error,
    transport::{FuturesIo, Runtime},
};

#[derive(Debug, Clone)]
pub struct ProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub transcript_secrets: Vec<tlsn::transcript::TranscriptSecret>,
    pub response_body: Vec<u8>,
}

pub struct Prover {
    runtime: Arc<dyn Runtime>,
    tls_client_config: TlsClientConfig,
    tls_commit_config: TlsCommitConfig,
    request: Request<Empty<Bytes>>,
    request_reveal_config: RevealConfig,
    response_reveal_config: RevealConfig,
    hash_alg: HashAlgId,
}

impl Prover {
    #[must_use]
    pub fn new(
        runtime: Arc<dyn Runtime>,
        tls_client_config: TlsClientConfig,
        tls_commit_config: TlsCommitConfig,
        request: Request<Empty<Bytes>>,
        request_reveal_config: RevealConfig,
        response_reveal_config: RevealConfig,
    ) -> Self {
        Self {
            runtime,
            tls_client_config,
            tls_commit_config,
            request,
            request_reveal_config,
            response_reveal_config,
            hash_alg: HashAlgId::POSEIDON2,
        }
    }

    pub async fn prove<T, S>(
        self,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<(T, ProverOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mpc_tls_connection, prover_fut, session_handle, verifier_io_rx) =
            Self::setup_and_connect(
                self.runtime,
                self.tls_client_config,
                self.tls_commit_config,
                verifier_socket,
                server_socket,
            )
            .await?;

        let (mut prover, response_body) =
            Self::execute_http_exchange(mpc_tls_connection, prover_fut, self.request).await?;

        let prove_config = Self::build_prove_config(
            &mut prover,
            self.hash_alg,
            &self.request_reveal_config,
            &self.response_reveal_config,
        )?;

        let sent = prover.transcript().sent().to_owned();
        let received = prover.transcript().received().to_owned();
        let prover_output = Self::generate_and_finalize_proof(prover, &prove_config).await?;

        session_handle.close();
        let verifier_io = verifier_io_rx
            .await
            .map_err(|_| Error::SessionDriverCancelled)
            .and_then(|inner| inner)?;

        Ok((
            verifier_io,
            ProverOutput {
                sent,
                received,
                transcript_commitments: prover_output.transcript_commitments,
                transcript_secrets: prover_output.transcript_secrets,
                response_body,
            },
        ))
    }

    async fn setup_and_connect<T, S>(
        runtime: Arc<dyn Runtime>,
        tls_client_config: TlsClientConfig,
        tls_commit_config: TlsCommitConfig,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<
        (
            impl AsyncRead + AsyncWrite + Send + Unpin,
            impl std::future::Future<
                Output = std::result::Result<
                    tlsn::prover::Prover<tlsn::prover::state::Committed>,
                    tlsn::Error,
                >,
            > + Send,
            SessionHandle,
            oneshot::Receiver<Result<T, Error>>,
        ),
        Error,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut session = Session::new(verifier_socket);
        let prover = session.new_prover(ProverConfig::builder().build()?)?;
        let (driver, handle) = session.split();
        let (verifier_io_tx, verifier_io_rx) = oneshot::channel();
        runtime.spawn_detached(Box::pin(async move {
            let outcome = driver.await.map_err(Error::from);
            let _ = verifier_io_tx.send(outcome);
        }));

        let prover = prover.commit(tls_commit_config).await?;
        let (connection, prover_future) = prover.connect(tls_client_config, server_socket)?;
        Ok((connection, prover_future, handle, verifier_io_rx))
    }

    async fn execute_http_exchange<C>(
        mpc_tls_connection: C,
        prover_fut: impl std::future::Future<
            Output = std::result::Result<
                tlsn::prover::Prover<tlsn::prover::state::Committed>,
                tlsn::Error,
            >,
        > + Send,
        request: Request<Empty<Bytes>>,
    ) -> Result<
        (
            tlsn::prover::Prover<tlsn::prover::state::Committed>,
            Vec<u8>,
        ),
        Error,
    >
    where
        C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mpc_tls_connection = FuturesIo::new(mpc_tls_connection);
        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

        let request_task = async move {
            let response = request_sender.send_request(request).await?;
            let status = response.status();

            if status != StatusCode::OK {
                return Err(Error::HttpRequestFailed(status.as_u16()));
            }

            Ok::<Vec<u8>, Error>(response.collect().await?.to_bytes().to_vec())
        };

        let (prover, connection_result, request_task_result) =
            join!(prover_fut, connection, request_task);

        Ok((prover?, {
            connection_result?;
            request_task_result?
        }))
    }

    fn build_prove_config(
        prover: &mut tlsn::prover::Prover<tlsn::prover::state::Committed>,
        hash_alg: HashAlgId,
        request_reveal_config: &RevealConfig,
        response_reveal_config: &RevealConfig,
    ) -> Result<ProveConfig, Error> {
        let transcript = prover.transcript();
        let mut prove_config_builder = ProveConfig::builder(transcript);
        prove_config_builder.server_identity();

        let mut transcript_commitment_builder = TranscriptCommitConfig::builder(transcript);
        transcript_commitment_builder
            .default_kind(TranscriptCommitmentKind::Hash { alg: hash_alg });

        reveal_request(
            transcript.sent(),
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            request_reveal_config,
        )?;

        reveal_response(
            transcript.received(),
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            response_reveal_config,
        )?;

        prove_config_builder.transcript_commit(transcript_commitment_builder.build()?);
        Ok(prove_config_builder.build()?)
    }

    async fn generate_and_finalize_proof(
        mut prover: tlsn::prover::Prover<tlsn::prover::state::Committed>,
        prove_config: &ProveConfig,
    ) -> Result<tlsn::prover::ProverOutput, Error> {
        let prover_output = prover.prove(prove_config).await?;
        prover.close().await?;
        Ok(prover_output)
    }
}
