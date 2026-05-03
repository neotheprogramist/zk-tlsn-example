use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite, channel::oneshot};
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    transcript::PartialTranscript,
};

use crate::{
    error::Error,
    parser::redacted::{Request, Response},
    transport::Runtime,
};

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub server_name: String,
    pub parsed_request: Request,
    pub parsed_response: Response,
}

pub struct VerifierConfigBundle {
    pub runtime: Arc<dyn Runtime>,
    pub config: VerifierConfig,
}

#[derive(Default)]
pub struct Verifier;

impl Verifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub async fn verify<T, P, R>(
        &self,
        config: VerifierConfigBundle,
        socket: T,
        protocol_policy: P,
        request_policy: R,
    ) -> Result<(T, VerifierOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        P: FnOnce(&TlsCommitProtocolConfig) -> Result<(), String>,
        R: FnOnce(bool, bool) -> Result<(), String>,
    {
        let VerifierConfigBundle {
            runtime,
            config: verifier_config,
        } = config;

        let mut session = Session::new(socket);
        let verifier = session.new_verifier(verifier_config)?;
        let (driver, handle) = session.split();

        let (socket_tx, socket_rx) = oneshot::channel();
        runtime.spawn_detached(Box::pin(async move {
            let outcome = driver.await.map_err(Error::from);
            // PROOF: the receiver is awaited below; if it has been dropped,
            // the verifier has already returned an error upstream and the
            // consumer side maps the closed channel to
            // `Error::SessionDriverCancelled`. We log the drop rather than
            // discard it silently so the event is observable in tracing.
            if socket_tx.send(outcome).is_err() {
                tracing::warn!("verifier socket oneshot receiver dropped before driver finished");
            }
        }));

        let verifier = verifier.commit().await?;
        if let Err(reason) = protocol_policy(verifier.request().protocol()) {
            verifier.reject(Some(&reason)).await?;
            return Err(Error::PolicyRejected {
                context: "protocol",
                reason,
            });
        }

        let verifier = verifier.accept().await?.run().await?.verify().await?;
        if let Err(reason) = request_policy(
            verifier.request().server_identity(),
            verifier.request().reveal().is_some(),
        ) {
            let verifier = verifier.reject(Some(&reason)).await?;
            verifier.close().await?;
            return Err(Error::PolicyRejected {
                context: "request",
                reason,
            });
        }

        let (output, verifier) = verifier.accept().await?;
        verifier.close().await?;
        handle.close();

        let socket = socket_rx
            .await
            .map_err(|_| Error::SessionDriverCancelled)
            .and_then(|inner| inner)?;

        let server_name = output
            .server_name
            .ok_or(Error::MissingField("server name"))?;
        let transcript = output.transcript.ok_or(Error::MissingField("transcript"))?;

        let sent_data = String::from_utf8(transcript.sent_unsafe().to_vec())?;
        let received_data = String::from_utf8(transcript.received_unsafe().to_vec())?;
        let parsed_request: Request = sent_data.parse()?;
        let parsed_response: Response = received_data.parse()?;

        Ok((
            socket,
            VerifierOutput {
                transcript,
                transcript_commitments: output.transcript_commitments,
                server_name: server_name.to_string(),
                parsed_request,
                parsed_response,
            },
        ))
    }
}
