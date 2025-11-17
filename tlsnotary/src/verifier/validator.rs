use tlsn::{hash::HashAlgId, transcript::Direction};

use crate::error::Error;

use super::VerifierOutput;

#[derive(Debug, Clone)]
pub struct Validator {
    expected_server_name: Option<String>,
    expected_hash_alg: Option<HashAlgId>,
    min_sent_data: Option<usize>,
    min_received_data: Option<usize>,
}

impl Validator {
    #[must_use]
    pub fn builder() -> ValidatorBuilder {
        ValidatorBuilder::new()
    }

    pub fn validate(&self, output: &VerifierOutput) -> Result<(), Error> {
        if let Some(expected_name) = &self.expected_server_name {
            if output.server_name != *expected_name {
                return Err(Error::InvalidTranscript(format!(
                    "Expected server name '{}', got '{}'",
                    expected_name, output.server_name
                )));
            }
        }

        if let Some(expected_alg) = self.expected_hash_alg {
            let received_commitment = output
                .transcript_commitments
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

            if received_commitment.hash.alg != expected_alg {
                return Err(Error::InvalidTranscript(format!(
                    "Expected {:?} hash algorithm, got {:?}",
                    expected_alg, received_commitment.hash.alg
                )));
            }
        }

        if let Some(min_sent) = self.min_sent_data {
            let sent_len = output.transcript.sent_unsafe().len();
            if sent_len < min_sent {
                return Err(Error::InvalidTranscript(format!(
                    "Expected at least {} bytes sent, got {}",
                    min_sent, sent_len
                )));
            }
        }

        if let Some(min_received) = self.min_received_data {
            let received_len = output.transcript.received_unsafe().len();
            if received_len < min_received {
                return Err(Error::InvalidTranscript(format!(
                    "Expected at least {} bytes received, got {}",
                    min_received, received_len
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ValidatorBuilder {
    expected_server_name: Option<String>,
    expected_hash_alg: Option<HashAlgId>,
    min_sent_data: Option<usize>,
    min_received_data: Option<usize>,
}

impl ValidatorBuilder {
    fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn expected_server_name(mut self, name: impl Into<String>) -> Self {
        self.expected_server_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn expected_hash_alg(mut self, alg: HashAlgId) -> Self {
        self.expected_hash_alg = Some(alg);
        self
    }

    #[must_use]
    pub fn min_sent_data(mut self, min: usize) -> Self {
        self.min_sent_data = Some(min);
        self
    }

    #[must_use]
    pub fn min_received_data(mut self, min: usize) -> Self {
        self.min_received_data = Some(min);
        self
    }

    #[must_use]
    pub fn build(self) -> Validator {
        Validator {
            expected_server_name: self.expected_server_name,
            expected_hash_alg: self.expected_hash_alg,
            min_sent_data: self.min_sent_data,
            min_received_data: self.min_received_data,
        }
    }
}
