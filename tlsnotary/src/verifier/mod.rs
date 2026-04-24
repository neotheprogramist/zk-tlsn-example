mod validator;

use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite, channel::oneshot};
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    transcript::PartialTranscript,
};
pub use validator::{ExpectedValue, FieldAssertion, Validator, ValidatorBuilder};

use crate::{error::Error, runtime::Runtime};

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub server_name: String,
    pub parsed_request: crate::parser::redacted::Request,
    pub parsed_response: crate::parser::redacted::Response,
}

pub struct Verifier {
    runtime: Arc<dyn Runtime>,
    verifier_config: VerifierConfig,
}

impl Verifier {
    #[must_use]
    pub fn new(runtime: Arc<dyn Runtime>, verifier_config: VerifierConfig) -> Self {
        Self {
            runtime,
            verifier_config,
        }
    }

    pub async fn verify<T>(
        self,
        socket: T,
        protocol_policy: impl FnOnce(&TlsCommitProtocolConfig) -> Result<(), String>,
        request_policy: impl FnOnce(bool, bool) -> Result<(), String>,
    ) -> Result<(T, VerifierOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut session = Session::new(socket);
        let verifier = session.new_verifier(self.verifier_config)?;
        let (driver, handle) = session.split();

        let (socket_tx, socket_rx) = oneshot::channel();
        self.runtime.spawn_detached(Box::pin(async move {
            let outcome = driver.await.map_err(Error::from);
            let _ = socket_tx.send(outcome);
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
        let parsed_request: crate::parser::redacted::Request = sent_data.parse()?;
        let parsed_response: crate::parser::redacted::Response = received_data.parse()?;

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
