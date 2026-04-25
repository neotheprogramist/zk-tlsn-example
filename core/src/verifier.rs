use std::collections::HashMap;

use futures::{AsyncRead, AsyncWrite, channel::oneshot};
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    hash::HashAlgId,
    transcript::PartialTranscript,
};

use crate::{
    error::{Error, TranscriptError},
    parser::redacted::{Body, Header, Request, Response},
};

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub server_name: String,
    pub parsed_request: Request,
    pub parsed_response: Response,
}

pub struct Verifier {
    verifier_config: VerifierConfig,
}

impl Verifier {
    #[must_use]
    pub fn new(verifier_config: VerifierConfig) -> Self {
        Self { verifier_config }
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
        smol::spawn(async move {
            let outcome = driver.await.map_err(Error::from);
            let _ = socket_tx.send(outcome);
        })
        .detach();

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

// ─── Validator ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum FieldAssertion {
    HeaderEquals { key: String, value: String },
    BodyFieldEquals { key: String, value: ExpectedValue },
}

#[derive(Debug, Clone)]
pub enum ExpectedValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone)]
enum ValidationRule {
    ServerName(String),
    HashAlgorithm(HashAlgId),
    Request(FieldAssertion),
    Response(FieldAssertion),
}

#[derive(Debug, Clone)]
pub struct Validator {
    rules: Vec<ValidationRule>,
}

impl Validator {
    #[must_use]
    pub fn builder() -> ValidatorBuilder {
        ValidatorBuilder::new()
    }

    pub fn validate(&self, output: &VerifierOutput) -> Result<(), Error> {
        for rule in &self.rules {
            match rule {
                ValidationRule::ServerName(expected_name) => {
                    if output.server_name != *expected_name {
                        return Err(TranscriptError::ServerName {
                            expected: expected_name.clone(),
                            actual: output.server_name.clone(),
                        }
                        .into());
                    }
                }
                ValidationRule::HashAlgorithm(expected_alg) => {
                    for commitment in &output.transcript_commitments {
                        if let tlsn::transcript::TranscriptCommitment::Hash(hash) = commitment
                            && hash.hash.alg != *expected_alg
                        {
                            return Err(TranscriptError::HashAlgorithm {
                                expected: *expected_alg,
                                actual: hash.hash.alg,
                                direction: hash.direction,
                            }
                            .into());
                        }
                    }
                }
                ValidationRule::Request(assertion) => {
                    Self::validate_assertion(
                        assertion,
                        &output.parsed_request.headers,
                        &output.parsed_request.body,
                        output.transcript.sent_unsafe(),
                        "request",
                    )?;
                }
                ValidationRule::Response(assertion) => {
                    Self::validate_assertion(
                        assertion,
                        &output.parsed_response.headers,
                        &output.parsed_response.body,
                        output.transcript.received_unsafe(),
                        "response",
                    )?;
                }
            }
        }

        Ok(())
    }

    fn validate_assertion(
        assertion: &FieldAssertion,
        headers: &HashMap<String, Vec<Header>>,
        body: &HashMap<String, Body>,
        data: &[u8],
        ctx: &'static str,
    ) -> Result<(), Error> {
        match assertion {
            FieldAssertion::HeaderEquals { key, value } => {
                let header = headers
                    .get(&key.to_lowercase())
                    .and_then(|h| h.first())
                    .ok_or_else(|| TranscriptError::MissingHeader {
                        ctx,
                        key: key.clone(),
                    })?;
                let range =
                    header
                        .value
                        .as_ref()
                        .ok_or_else(|| TranscriptError::HeaderWithoutValue {
                            ctx,
                            key: key.clone(),
                        })?;
                let actual = std::str::from_utf8(&data[range.clone()])?;
                if actual != value {
                    return Err(TranscriptError::HeaderMismatch {
                        ctx,
                        key: key.clone(),
                        expected: value.clone(),
                        actual: actual.to_string(),
                    }
                    .into());
                }
            }
            FieldAssertion::BodyFieldEquals { key, value } => {
                let field = body
                    .get(key)
                    .ok_or_else(|| TranscriptError::MissingBodyField {
                        ctx,
                        key: key.clone(),
                    })?;
                Self::validate_value(value, field, data, ctx, key)?;
            }
        }
        Ok(())
    }

    fn validate_value(
        expected: &ExpectedValue,
        field: &Body,
        data: &[u8],
        ctx: &'static str,
        key: &str,
    ) -> Result<(), Error> {
        let range = match field {
            Body::KeyValue { value, .. } => value.as_ref(),
            Body::Value(r) => Some(r),
        }
        .ok_or_else(|| TranscriptError::MissingFieldValue {
            ctx,
            key: key.to_string(),
        })?;

        let actual = std::str::from_utf8(&data[range.clone()])?;

        let mismatch = |expected: String, actual: String| TranscriptError::FieldMismatch {
            ctx,
            key: key.to_string(),
            expected,
            actual,
        };

        match expected {
            ExpectedValue::Null if actual == "null" => Ok(()),
            ExpectedValue::Null => Err(mismatch("null".into(), actual.to_string()).into()),
            ExpectedValue::Bool(exp) => match actual.parse::<bool>() {
                Ok(act) if &act == exp => Ok(()),
                Ok(act) => Err(mismatch(exp.to_string(), act.to_string()).into()),
                Err(_) => Err(mismatch(exp.to_string(), actual.to_string()).into()),
            },
            ExpectedValue::Number(exp) => match actual.parse::<f64>() {
                Ok(act) if (exp - act).abs() < f64::EPSILON => Ok(()),
                Ok(act) => Err(mismatch(exp.to_string(), act.to_string()).into()),
                Err(_) => Err(mismatch(exp.to_string(), actual.to_string()).into()),
            },
            ExpectedValue::String(exp) if exp == actual => Ok(()),
            ExpectedValue::String(exp) => {
                Err(mismatch(format!("'{exp}'"), format!("'{actual}'")).into())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidatorBuilder {
    rules: Vec<ValidationRule>,
}

impl ValidatorBuilder {
    fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn expected_server_name(mut self, name: impl Into<String>) -> Self {
        self.rules.push(ValidationRule::ServerName(name.into()));
        self
    }

    #[must_use]
    pub fn expected_hash_alg(mut self, alg: HashAlgId) -> Self {
        self.rules.push(ValidationRule::HashAlgorithm(alg));
        self
    }

    #[must_use]
    pub fn request_header_equals(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.rules
            .push(ValidationRule::Request(FieldAssertion::HeaderEquals {
                key: key.into(),
                value: value.into(),
            }));
        self
    }

    #[must_use]
    pub fn response_header_equals(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.rules
            .push(ValidationRule::Response(FieldAssertion::HeaderEquals {
                key: key.into(),
                value: value.into(),
            }));
        self
    }

    #[must_use]
    pub fn request_body_field_equals(
        mut self,
        key: impl Into<String>,
        value: ExpectedValue,
    ) -> Self {
        self.rules
            .push(ValidationRule::Request(FieldAssertion::BodyFieldEquals {
                key: key.into(),
                value,
            }));
        self
    }

    #[must_use]
    pub fn response_body_field_equals(
        mut self,
        key: impl Into<String>,
        value: ExpectedValue,
    ) -> Self {
        self.rules
            .push(ValidationRule::Response(FieldAssertion::BodyFieldEquals {
                key: key.into(),
                value,
            }));
        self
    }

    #[must_use]
    pub fn build(self) -> Validator {
        Validator { rules: self.rules }
    }
}
