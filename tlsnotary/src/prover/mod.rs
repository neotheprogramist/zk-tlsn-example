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
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub transcript_secrets: Vec<tlsn::transcript::TranscriptSecret>,
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
        tracing::info!(component = "prover", phase = "setup", status = "started");
        let prover = TlsnProver::new(self.prover_config)
            .setup(verifier_socket)
            .await
            .map_err(|e| Error::ProverSetup(e.to_string()))?;
        tracing::info!(component = "prover", phase = "setup", status = "completed");

        tracing::info!(component = "prover", phase = "connect", status = "started");
        let (mpc_tls_connection, prover_fut) = prover
            .connect(server_socket)
            .await
            .map_err(|e| Error::ProverConnection(e.to_string()))?;
        tracing::info!(
            component = "prover",
            phase = "connect",
            status = "completed"
        );

        let mpc_tls_connection = TokioIo::new(Compat::new(mpc_tls_connection));

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(mpc_tls_connection)
                .await
                .map_err(|e| Error::MpcTlsHandshake(e.to_string()))?;

        let request_task = async move {
            tracing::info!(
                component = "prover",
                phase = "http_exchange",
                status = "started"
            );
            let response = request_sender.send_request(self.request).await?;
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

            let response = response.collect().await?;
            tracing::info!(
                component = "prover",
                phase = "http_exchange",
                status = "completed",
                http_status = status.as_u16()
            );

            Ok(response)
        };

        let (prover, connection_result, response) = join!(prover_fut, connection, request_task);
        let mut prover = prover?;
        connection_result?;
        let response = response?;

        let transcript = prover.transcript().clone();
        let mut prove_config_builder = ProveConfig::builder(&transcript);

        prove_config_builder.server_identity();

        let sent: &[u8] = transcript.sent();
        let received: &[u8] = transcript.received();
        let sent_len = sent.len();
        let recv_len = received.len();

        let mut transcript_commitment_builder = TranscriptCommitConfig::builder(&transcript);
        transcript_commitment_builder
            .default_kind(TranscriptCommitmentKind::Hash { alg: self.hash_alg });

        reveal_request(
            sent,
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            &self.request_reveal_config,
        )?;

        reveal_response(
            received,
            &mut prove_config_builder,
            &mut transcript_commitment_builder,
            &self.response_reveal_config,
        )?;

        let transcripts_commitment_config = transcript_commitment_builder.build()?;
        prove_config_builder.transcript_commit(transcripts_commitment_config);

        let prove_config = prove_config_builder.build()?;

        tracing::info!(
            component = "prover",
            phase = "prove",
            status = "started",
            sent_len,
            recv_len
        );
        let prover_output = prover
            .prove(&prove_config)
            .await
            .map_err(|e| Error::ProveFailed(e.to_string()))?;
        tracing::info!(component = "prover", phase = "prove", status = "completed");

        prover
            .close()
            .await
            .map_err(|e| Error::ProveFailed(e.to_string()))?;
        Ok(ProverOutput {
            transcript_commitments: prover_output.transcript_commitments,
            transcript_secrets: prover_output.transcript_secrets,
        })
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
            hash_alg: HashAlgId::SHA256,
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
