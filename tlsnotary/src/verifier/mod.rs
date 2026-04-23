mod validator;

use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite, FutureExt};
use tlsn::{Session, config::verifier::VerifierConfig, transcript::PartialTranscript};
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
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    pub async fn verify<T>(self, socket: T) -> Result<VerifierOutput, Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut session = Session::new(socket);
        let verifier = session.new_verifier(self.verifier_config)?;
        let (driver, handle) = session.split();
        self.runtime.spawn_detached(Box::pin(driver.map(|_| ())));

        let verifier = verifier.commit().await?;
        let verifier = verifier.accept().await?;
        let verifier = verifier.run().await?;
        let verifier = verifier.verify().await?;
        let (output, verifier) = verifier.accept().await?;
        verifier.close().await?;
        handle.close();

        let server_name = output
            .server_name
            .ok_or(Error::MissingField("server name"))?;
        let transcript = output.transcript.ok_or(Error::MissingField("transcript"))?;

        let sent_data = String::from_utf8(transcript.sent_unsafe().to_vec())?;
        let received_data = String::from_utf8(transcript.received_unsafe().to_vec())?;
        let parsed_request: crate::parser::redacted::Request = sent_data.parse()?;
        let parsed_response: crate::parser::redacted::Response = received_data.parse()?;

        Ok(VerifierOutput {
            transcript,
            transcript_commitments: output.transcript_commitments,
            server_name: server_name.to_string(),
            parsed_request,
            parsed_response,
        })
    }
}

pub struct VerifierBuilder {
    runtime: Option<Arc<dyn Runtime>>,
    verifier_config: Option<VerifierConfig>,
}

impl VerifierBuilder {
    fn new() -> Self {
        Self {
            runtime: None,
            verifier_config: None,
        }
    }

    #[must_use]
    pub fn runtime(mut self, runtime: Arc<dyn Runtime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    #[must_use]
    pub fn verifier_config(mut self, config: VerifierConfig) -> Self {
        self.verifier_config = Some(config);
        self
    }

    pub fn build(self) -> Result<Verifier, Error> {
        Ok(Verifier {
            runtime: self.runtime.ok_or(Error::MissingBuilderField("runtime"))?,
            verifier_config: self
                .verifier_config
                .ok_or(Error::MissingBuilderField("verifier_config"))?,
        })
    }
}
