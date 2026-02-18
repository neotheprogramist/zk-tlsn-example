mod validator;

use futures::{AsyncRead, AsyncWrite};
use tlsn::{Session, config::verifier::VerifierConfig, transcript::PartialTranscript};
pub use validator::{ExpectedValue, FieldAssertion, Validator, ValidatorBuilder};

use crate::error::Error;

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub server_name: String,
    pub parsed_request: Option<parser::redacted::Request>,
    pub parsed_response: Option<parser::redacted::Response>,
}

pub struct Verifier {
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
        smol::spawn(driver).detach();

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

        Ok(VerifierOutput {
            transcript,
            transcript_commitments: output.transcript_commitments,
            server_name: server_name.to_string(),
            parsed_request: sent_data.parse().ok(),
            parsed_response: received_data.parse().ok(),
        })
    }
}

#[derive(Debug)]
pub struct VerifierBuilder {
    verifier_config: Option<VerifierConfig>,
}

impl VerifierBuilder {
    fn new() -> Self {
        Self {
            verifier_config: None,
        }
    }

    #[must_use]
    pub fn verifier_config(mut self, config: VerifierConfig) -> Self {
        self.verifier_config = Some(config);
        self
    }

    pub fn build(self) -> Result<Verifier, Error> {
        Ok(Verifier {
            verifier_config: self
                .verifier_config
                .ok_or_else(|| Error::InvalidConfig("verifier_config is required".into()))?,
        })
    }
}
