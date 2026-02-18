mod reveal;

use async_compat::Compat;
use futures::{AsyncRead, AsyncWrite, join};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
pub use reveal::{
    BodyFieldConfig, KeyValueCommitConfig, RevealConfig, reveal_request, reveal_response,
};
use tlsn::{
    Session, SessionHandle,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::TlsCommitConfig,
    },
    hash::HashAlgId,
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
    tls_client_config: TlsClientConfig,
    tls_commit_config: TlsCommitConfig,
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
        let (mpc_tls_connection, prover_fut, session_handle) = Self::setup_and_connect(
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

        Ok(ProverOutput {
            sent,
            received,
            transcript_commitments: prover_output.transcript_commitments,
            transcript_secrets: prover_output.transcript_secrets,
            response_body,
        })
    }

    async fn setup_and_connect<T, S>(
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
        smol::spawn(driver).detach();

        let prover = prover.commit(tls_commit_config).await?;
        let (connection, prover_future) = prover.connect(tls_client_config, server_socket).await?;
        Ok((connection, prover_future, handle))
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
        let mpc_tls_connection = TokioIo::new(Compat::new(mpc_tls_connection));
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
        let transcript = prover.transcript().clone();
        let mut prove_config_builder = ProveConfig::builder(&transcript);
        prove_config_builder.server_identity();

        let mut transcript_commitment_builder = TranscriptCommitConfig::builder(&transcript);
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

#[derive(Debug)]
pub struct ProverBuilder {
    tls_client_config: Option<TlsClientConfig>,
    tls_commit_config: Option<TlsCommitConfig>,
    request: Option<Request<Empty<Bytes>>>,
    request_reveal_config: RevealConfig,
    response_reveal_config: RevealConfig,
    hash_alg: HashAlgId,
}

impl ProverBuilder {
    fn new() -> Self {
        Self {
            tls_client_config: None,
            tls_commit_config: None,
            request: None,
            request_reveal_config: RevealConfig::default(),
            response_reveal_config: RevealConfig::default(),
            hash_alg: HashAlgId::BLAKE3,
        }
    }

    #[must_use]
    pub fn tls_client_config(mut self, config: TlsClientConfig) -> Self {
        self.tls_client_config = Some(config);
        self
    }

    #[must_use]
    pub fn tls_commit_config(mut self, config: TlsCommitConfig) -> Self {
        self.tls_commit_config = Some(config);
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
        Ok(Prover {
            tls_client_config: self
                .tls_client_config
                .ok_or_else(|| Error::InvalidConfig("tls_client_config is required".into()))?,
            tls_commit_config: self
                .tls_commit_config
                .ok_or_else(|| Error::InvalidConfig("tls_commit_config is required".into()))?,
            request: self
                .request
                .ok_or_else(|| Error::InvalidConfig("request is required".into()))?,
            request_reveal_config: self.request_reveal_config,
            response_reveal_config: self.response_reveal_config,
            hash_alg: self.hash_alg,
        })
    }
}
