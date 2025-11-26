use std::collections::HashMap;

use tlsn::hash::HashAlgId;

use super::VerifierOutput;
use crate::error::Error;

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
pub struct Validator {
    expected_server_name: Option<String>,
    expected_hash_alg: Option<HashAlgId>,
    request_assertions: Vec<FieldAssertion>,
    response_assertions: Vec<FieldAssertion>,
}

impl Validator {
    #[must_use]
    pub fn builder() -> ValidatorBuilder {
        ValidatorBuilder::new()
    }

    pub fn validate(&self, output: &VerifierOutput) -> Result<(), Error> {
        if let Some(expected_name) = &self.expected_server_name
            && output.server_name != *expected_name
        {
            return Err(Error::InvalidTranscript(format!(
                "Expected server name '{}', got '{}'",
                expected_name, output.server_name
            )));
        }

        if let Some(expected_alg) = self.expected_hash_alg {
            for commitment in &output.transcript_commitments {
                if let tlsn::transcript::TranscriptCommitment::Hash(hash) = commitment
                    && hash.hash.alg != expected_alg
                {
                    return Err(Error::InvalidTranscript(format!(
                        "Expected {:?} hash algorithm in {:?} direction, got {:?}",
                        expected_alg, hash.direction, hash.hash.alg
                    )));
                }
            }
        }

        if !self.request_assertions.is_empty() {
            let request = output
                .parsed_request
                .as_ref()
                .ok_or(Error::MissingField("parsed request"))?;

            let request_data = output.transcript.sent_unsafe();

            for assertion in &self.request_assertions {
                Self::validate_assertion(
                    assertion,
                    &request.headers,
                    &request.body,
                    request_data,
                    "request",
                )?;
            }
        }

        if !self.response_assertions.is_empty() {
            let response = output
                .parsed_response
                .as_ref()
                .ok_or(Error::MissingField("parsed response"))?;

            let response_data = output.transcript.received_unsafe();

            for assertion in &self.response_assertions {
                Self::validate_assertion(
                    assertion,
                    &response.headers,
                    &response.body,
                    response_data,
                    "response",
                )?;
            }
        }

        Ok(())
    }

    fn validate_assertion(
        assertion: &FieldAssertion,
        headers: &HashMap<String, Vec<parser::redacted::Header>>,
        body: &HashMap<String, parser::redacted::Body>,
        data: &[u8],
        ctx: &str,
    ) -> Result<(), Error> {
        match assertion {
            FieldAssertion::HeaderEquals { key, value } => {
                let header = headers
                    .get(&key.to_lowercase())
                    .and_then(|h| h.first())
                    .ok_or_else(|| {
                        Error::InvalidTranscript(format!("Missing {ctx} header '{key}'"))
                    })?;
                let range = header.value.as_ref().ok_or_else(|| {
                    Error::InvalidTranscript(format!("{ctx} header '{key}' has no value"))
                })?;
                let actual = std::str::from_utf8(&data[range.clone()])
                    .map_err(|_| Error::InvalidTranscript("Invalid UTF-8".into()))?;
                if actual != value {
                    return Err(Error::InvalidTranscript(format!(
                        "{ctx} header '{key}': expected '{value}', got '{actual}'"
                    )));
                }
            }
            FieldAssertion::BodyFieldEquals { key, value } => {
                let field = body.get(key).ok_or_else(|| {
                    Error::InvalidTranscript(format!("Missing {ctx} body field '{key}'"))
                })?;
                Self::validate_value(value, field, data, ctx, key)?;
            }
        }
        Ok(())
    }

    fn validate_value(
        expected: &ExpectedValue,
        field: &parser::redacted::Body,
        data: &[u8],
        ctx: &str,
        key: &str,
    ) -> Result<(), Error> {
        let range = match field {
            parser::redacted::Body::KeyValue { value, .. } => value.as_ref(),
            parser::redacted::Body::Value(r) => Some(r),
        }
        .ok_or_else(|| {
            Error::InvalidTranscript(format!("Missing value for {ctx} field '{key}'"))
        })?;

        let actual = std::str::from_utf8(&data[range.clone()])
            .map_err(|_| Error::InvalidTranscript("Invalid UTF-8".into()))?;

        let mismatch = |exp: &dyn std::fmt::Display, act: &dyn std::fmt::Display| {
            Error::InvalidTranscript(format!("{ctx} field '{key}': expected {exp}, got {act}"))
        };

        match expected {
            ExpectedValue::Null if actual == "null" => Ok(()),
            ExpectedValue::Null => Err(mismatch(&"null", &actual)),
            ExpectedValue::Bool(exp) => actual
                .parse::<bool>()
                .map_err(|_| mismatch(exp, &actual))
                .and_then(|act| {
                    if &act == exp {
                        Ok(())
                    } else {
                        Err(mismatch(exp, &act))
                    }
                }),
            ExpectedValue::Number(exp) => actual
                .parse::<f64>()
                .map_err(|_| mismatch(exp, &actual))
                .and_then(|act| {
                    if (exp - act).abs() < f64::EPSILON {
                        Ok(())
                    } else {
                        Err(mismatch(exp, &act))
                    }
                }),
            ExpectedValue::String(exp) if exp == actual => Ok(()),
            ExpectedValue::String(exp) => {
                Err(mismatch(&format!("'{exp}'"), &format!("'{actual}'")))
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidatorBuilder {
    expected_server_name: Option<String>,
    expected_hash_alg: Option<HashAlgId>,
    request_assertions: Vec<FieldAssertion>,
    response_assertions: Vec<FieldAssertion>,
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
    pub fn request_header_equals(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.request_assertions.push(FieldAssertion::HeaderEquals {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    #[must_use]
    pub fn response_header_equals(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.response_assertions.push(FieldAssertion::HeaderEquals {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    #[must_use]
    pub fn request_body_field_equals(
        mut self,
        key: impl Into<String>,
        value: ExpectedValue,
    ) -> Self {
        self.request_assertions
            .push(FieldAssertion::BodyFieldEquals {
                key: key.into(),
                value,
            });
        self
    }

    #[must_use]
    pub fn response_body_field_equals(
        mut self,
        key: impl Into<String>,
        value: ExpectedValue,
    ) -> Self {
        self.response_assertions
            .push(FieldAssertion::BodyFieldEquals {
                key: key.into(),
                value,
            });
        self
    }

    #[must_use]
    pub fn build(self) -> Validator {
        Validator {
            expected_server_name: self.expected_server_name,
            expected_hash_alg: self.expected_hash_alg,
            request_assertions: self.request_assertions,
            response_assertions: self.response_assertions,
        }
    }
}
