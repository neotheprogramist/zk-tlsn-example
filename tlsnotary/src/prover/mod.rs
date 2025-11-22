mod reveal;

use async_compat::Compat;
use futures::{AsyncRead, AsyncWrite, join};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
pub use reveal::{RevealConfig, reveal_request, reveal_response};
use tlsn::{
    hash::HashAlgId,
    prover::{ProveConfig, Prover as TlsnProver, ProverConfig},
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
};

use crate::error::Error;

#[derive(Debug, Clone)]
pub struct ProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub transcript_secrets: Vec<tlsn::transcript::TranscriptSecret>,
    pub response_body: Vec<u8>,
}

pub struct Prover {
    prover_config: ProverConfig,
    request: Request<Empty<Bytes>>,
    request_reveal_config: RevealConfig,
    response_reveal_config: RevealConfig,
    hash_alg: HashAlgId,
}

impl Prover {
    #[must_use]
    pub fn builder() -> ProverBuilder {
        ProverBuilder::new()
    }

    pub async fn prove<T, S>(
        self,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<ProverOutput, Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        tracing::info!(component = "prover", phase = "prove", status = "started");

        let (mpc_tls_connection, prover_fut) =
            Self::setup_and_connect(self.prover_config, verifier_socket, server_socket).await?;

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

        tracing::info!(component = "prover", phase = "prove", status = "completed");

        Ok(ProverOutput {
            sent,
            received,
            transcript_commitments: prover_output.transcript_commitments,
            transcript_secrets: prover_output.transcript_secrets,
            response_body,
        })
    }

    async fn setup_and_connect<T, S>(
        config: ProverConfig,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<
        (
            impl AsyncRead + AsyncWrite + Send + Unpin,
            impl std::future::Future<
                Output = Result<
                    tlsn::prover::Prover<tlsn::prover::state::Committed>,
                    tlsn::prover::ProverError,
                >,
            > + Send,
        ),
        Error,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        tracing::info!(component = "prover", phase = "setup", status = "started");

        let prover = TlsnProver::new(config).setup(verifier_socket).await?;

        tracing::info!(component = "prover", phase = "setup", status = "completed");
        tracing::info!(component = "prover", phase = "connect", status = "started");

        let (mpc_tls_connection, prover_fut) = prover.connect(server_socket).await?;

        tracing::info!(
            component = "prover",
            phase = "connect",
            status = "completed"
        );

        Ok((mpc_tls_connection, prover_fut))
    }

    async fn execute_http_exchange<C>(
        mpc_tls_connection: C,
        prover_fut: impl std::future::Future<
            Output = Result<
                tlsn::prover::Prover<tlsn::prover::state::Committed>,
                tlsn::prover::ProverError,
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
        let mpc_tls_connection = TokioIo::new(Compat::new(mpc_tls_connection));

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

        let request_task = async move {
            tracing::info!(
                component = "prover",
                phase = "http_exchange",
                status = "started"
            );
            let response = request_sender.send_request(request).await?;
            let status = response.status();

            if status != StatusCode::OK {
                tracing::error!(
                    component = "prover",
                    phase = "http_exchange",
                    status = "failed",
                    http_status = status.as_u16()
                );
                return Err(Error::HttpRequestFailed(status.as_u16()));
            }

            let body = response.collect().await?.to_bytes();
            tracing::info!(
                component = "prover",
                phase = "http_exchange",
                status = "completed",
                http_status = status.as_u16()
            );

            Ok::<Vec<u8>, Error>(body.to_vec())
        };

        let (prover, connection_result, request_task_result) =
            join!(prover_fut, connection, request_task);

        let prover = prover?;
        connection_result?;
        let response_body = request_task_result?;

        Ok((prover, response_body))
    }

    fn build_prove_config(
        prover: &mut tlsn::prover::Prover<tlsn::prover::state::Committed>,
        hash_alg: HashAlgId,
        request_reveal_config: &RevealConfig,
        response_reveal_config: &RevealConfig,
    ) -> Result<ProveConfig, Error> {
        let transcript = prover.transcript().clone();
        let mut prove_config_builder = ProveConfig::builder(&transcript);

        prove_config_builder.server_identity();

        let sent: &[u8] = transcript.sent();
        let received: &[u8] = transcript.received();

        let mut transcript_commitment_builder = TranscriptCommitConfig::builder(&transcript);
        transcript_commitment_builder
            .default_kind(TranscriptCommitmentKind::Hash { alg: hash_alg });

        reveal_request(
            sent,
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            request_reveal_config,
        )?;

        reveal_response(
            received,
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            response_reveal_config,
        )?;

        let transcripts_commitment_config = transcript_commitment_builder.build()?;
        prove_config_builder.transcript_commit(transcripts_commitment_config);

        Ok(prove_config_builder.build()?)
    }

    async fn generate_and_finalize_proof(
        mut prover: tlsn::prover::Prover<tlsn::prover::state::Committed>,
        prove_config: &ProveConfig,
    ) -> Result<tlsn::prover::ProverOutput, Error> {
        let sent_len = prover.transcript().sent().len();
        let recv_len = prover.transcript().received().len();

        tracing::info!(
            component = "prover",
            phase = "generate_proof",
            status = "started",
            sent_len,
            recv_len
        );

        let prover_output = prover.prove(prove_config).await?;

        tracing::info!(
            component = "prover",
            phase = "generate_proof",
            status = "completed"
        );

        prover.close().await?;

        Ok(prover_output)
    }
}

#[derive(Debug)]
pub struct ProverBuilder {
    prover_config: Option<ProverConfig>,
    request: Option<Request<Empty<Bytes>>>,
    request_reveal_config: RevealConfig,
    response_reveal_config: RevealConfig,
    hash_alg: HashAlgId,
}

impl ProverBuilder {
    fn new() -> Self {
        Self {
            prover_config: None,
            request: None,
            request_reveal_config: RevealConfig::default(),
            response_reveal_config: RevealConfig::default(),
            hash_alg: HashAlgId::BLAKE3,
        }
    }

    #[must_use]
    pub fn prover_config(mut self, config: ProverConfig) -> Self {
        self.prover_config = Some(config);
        self
    }

    #[must_use]
    pub fn request(mut self, request: Request<Empty<Bytes>>) -> Self {
        self.request = Some(request);
        self
    }

    #[must_use]
    pub fn request_reveal_config(mut self, config: RevealConfig) -> Self {
        self.request_reveal_config = config;
        self
    }

    #[must_use]
    pub fn response_reveal_config(mut self, config: RevealConfig) -> Self {
        self.response_reveal_config = config;
        self
    }

    #[must_use]
    pub fn hash_alg(mut self, alg: HashAlgId) -> Self {
        self.hash_alg = alg;
        self
    }

    pub fn build(self) -> Result<Prover, Error> {
        let prover_config = self
            .prover_config
            .ok_or_else(|| Error::InvalidConfig("prover_config is required".into()))?;
        let request = self
            .request
            .ok_or_else(|| Error::InvalidConfig("request is required".into()))?;

        Ok(Prover {
            prover_config,
            request,
            request_reveal_config: self.request_reveal_config,
            response_reveal_config: self.response_reveal_config,
            hash_alg: self.hash_alg,
        })
    }
}
