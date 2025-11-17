use futures::{AsyncRead, AsyncWrite};
use parser::{RedactedRequestParser, RedactedResponseParser};
use tlsn::{
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript},
    verifier::{Verifier as TlsnVerifier, VerifierConfig, VerifyConfig},
};

use crate::{error::ZkTlsNotaryError, transcript::extract_received_commitments};

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub server_name: String,
    pub parsed_request: Option<parser::redacted::Request>,
    pub parsed_response: Option<parser::redacted::Response>,
}

pub struct Verifier {
    verifier_config: VerifierConfig,
    hash_alg: HashAlgId,
}

impl Verifier {
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    pub async fn verify<T>(self, socket: T) -> Result<VerifierOutput, ZkTlsNotaryError>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        tracing::info!(component = "verifier", phase = "verify", status = "started");

        let verifier = TlsnVerifier::new(self.verifier_config);

        let verifier_output = verifier
            .verify(socket, &VerifyConfig::default())
            .await
            .map_err(|e| ZkTlsNotaryError::VerifyFailed(e.to_string()))?;

        let server_name = verifier_output
            .server_name
            .ok_or(ZkTlsNotaryError::MissingField("server name"))?;

        let transcript = verifier_output
            .transcript
            .ok_or(ZkTlsNotaryError::MissingField("transcript"))?;

        let received_commitments =
            extract_received_commitments(&verifier_output.transcript_commitments);
        let received_commitment = received_commitments
            .first()
            .ok_or(ZkTlsNotaryError::MissingField("received hash commitment"))?;

        if received_commitment.direction != Direction::Received {
            return Err(ZkTlsNotaryError::InvalidTranscript(
                "Expected received direction for commitment".into(),
            ));
        }

        if received_commitment.hash.alg != self.hash_alg {
            return Err(ZkTlsNotaryError::InvalidTranscript(format!(
                "Expected {:?} hash algorithm",
                self.hash_alg
            )));
        }

        let sent_data = String::from_utf8(transcript.sent_unsafe().to_vec()).map_err(|_| {
            ZkTlsNotaryError::InvalidTranscript("Sent data is not valid UTF-8".into())
        })?;
        let received_data =
            String::from_utf8(transcript.received_unsafe().to_vec()).map_err(|_| {
                ZkTlsNotaryError::InvalidTranscript("Received data is not valid UTF-8".into())
            })?;

        let parsed_request = RedactedRequestParser::parse_redacted_request(&sent_data).ok();
        let parsed_response = RedactedResponseParser::parse_redacted_response(&received_data).ok();

        tracing::info!(
            component = "verifier",
            phase = "verify",
            status = "completed",
            server_name = %server_name
        );

        Ok(VerifierOutput {
            transcript,
            server_name: server_name.to_string(),
            parsed_request,
            parsed_response,
        })
    }
}

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

    pub fn verifier_config(mut self, config: VerifierConfig) -> Self {
        self.verifier_config = Some(config);
        self
    }

    pub fn hash_alg(mut self, alg: HashAlgId) -> Self {
        self.hash_alg = alg;
        self
    }

    pub fn build(self) -> Result<Verifier, ZkTlsNotaryError> {
        let verifier_config = self
            .verifier_config
            .ok_or_else(|| ZkTlsNotaryError::InvalidConfig("verifier_config is required".into()))?;

        Ok(Verifier {
            verifier_config,
            hash_alg: self.hash_alg,
        })
    }
}
