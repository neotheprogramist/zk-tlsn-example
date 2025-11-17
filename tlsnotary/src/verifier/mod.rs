use futures::{AsyncRead, AsyncWrite};
use parser::{RedactedRequestParser, RedactedResponseParser};
use tlsn::{
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript},
    verifier::{Verifier as TlsnVerifier, VerifierConfig, VerifyConfig},
};

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
    hash_alg: HashAlgId,
}

impl Verifier {
    #[must_use]
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    pub async fn verify<T>(self, socket: T) -> Result<VerifierOutput, Error>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        tracing::info!(component = "verifier", phase = "verify", status = "started");

        let verifier_output = Self::run_verify(self.verifier_config, socket).await?;

        let (server_name, transcript) =
            Self::extract_core_data(verifier_output.server_name, verifier_output.transcript)?;

        Self::validate_commitments(&verifier_output.transcript_commitments, self.hash_alg)?;

        let (parsed_request, parsed_response) = Self::parse_transcript_data(&transcript)?;

        tracing::info!(component = "verifier", phase = "verify", status = "completed", server_name = %server_name);

        Ok(VerifierOutput {
            transcript,
            transcript_commitments: verifier_output.transcript_commitments,
            server_name: server_name.to_string(),
            parsed_request,
            parsed_response,
        })
    }

    async fn run_verify<T>(
        config: VerifierConfig,
        socket: T,
    ) -> Result<tlsn::verifier::VerifierOutput, Error>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let verifier = TlsnVerifier::new(config);
        verifier
            .verify(socket, &VerifyConfig::default())
            .await
            .map_err(|e| Error::VerifyFailed(e.to_string()))
    }

    fn extract_core_data(
        server_name: Option<tlsn::connection::ServerName>,
        transcript: Option<PartialTranscript>,
    ) -> Result<(tlsn::connection::ServerName, PartialTranscript), Error> {
        let server_name = server_name.ok_or(Error::MissingField("server name"))?;
        let transcript = transcript.ok_or(Error::MissingField("transcript"))?;
        Ok((server_name, transcript))
    }

    fn validate_commitments(
        transcript_commitments: &[tlsn::transcript::TranscriptCommitment],
        expected_hash_alg: HashAlgId,
    ) -> Result<(), Error> {
        let received_commitment = transcript_commitments
            .iter()
            .find_map(|commitment| match commitment {
                tlsn::transcript::TranscriptCommitment::Hash(hash)
                    if hash.direction == Direction::Received =>
                {
                    Some(hash)
                }
                _ => None,
            })
            .ok_or(Error::MissingField("received hash commitment"))?;

        if received_commitment.hash.alg != expected_hash_alg {
            return Err(Error::InvalidTranscript(format!(
                "Expected {:?} hash algorithm",
                expected_hash_alg
            )));
        }

        Ok(())
    }

    fn parse_transcript_data(
        transcript: &PartialTranscript,
    ) -> Result<
        (
            Option<parser::redacted::Request>,
            Option<parser::redacted::Response>,
        ),
        Error,
    > {
        let sent_data = String::from_utf8(transcript.sent_unsafe().to_vec())
            .map_err(|_| Error::InvalidTranscript("Sent data is not valid UTF-8".into()))?;
        let received_data = String::from_utf8(transcript.received_unsafe().to_vec())
            .map_err(|_| Error::InvalidTranscript("Received data is not valid UTF-8".into()))?;

        let parsed_request = RedactedRequestParser::parse_redacted_request(&sent_data).ok();
        let parsed_response = RedactedResponseParser::parse_redacted_response(&received_data).ok();

        Ok((parsed_request, parsed_response))
    }
}

#[derive(Debug)]
pub struct VerifierBuilder {
    verifier_config: Option<VerifierConfig>,
    hash_alg: HashAlgId,
}

impl VerifierBuilder {
    fn new() -> Self {
        Self {
            verifier_config: None,
            hash_alg: HashAlgId::SHA256,
        }
    }

    #[must_use]
    pub fn verifier_config(mut self, config: VerifierConfig) -> Self {
        self.verifier_config = Some(config);
        self
    }

    #[must_use]
    pub fn hash_alg(mut self, alg: HashAlgId) -> Self {
        self.hash_alg = alg;
        self
    }

    pub fn build(self) -> Result<Verifier, Error> {
        let verifier_config = self
            .verifier_config
            .ok_or_else(|| Error::InvalidConfig("verifier_config is required".into()))?;

        Ok(Verifier {
            verifier_config,
            hash_alg: self.hash_alg,
        })
    }
}
