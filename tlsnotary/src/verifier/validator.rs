use std::collections::HashMap;

use parser::{RangedText, RangedValue};
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

            for assertion in &self.request_assertions {
                Self::validate_assertion(assertion, &request.headers, &request.body, "request")?;
            }
        }

        if !self.response_assertions.is_empty() {
            let response = output
                .parsed_response
                .as_ref()
                .ok_or(Error::MissingField("parsed response"))?;

            for assertion in &self.response_assertions {
                Self::validate_assertion(assertion, &response.headers, &response.body, "response")?;
            }
        }

        Ok(())
    }

    fn validate_assertion(
        assertion: &FieldAssertion,
        headers: &HashMap<String, RangedText>,
        body: &HashMap<String, RangedValue>,
        context: &str,
    ) -> Result<(), Error> {
        match assertion {
            FieldAssertion::HeaderEquals { key, value } => {
                let actual = headers
                    .get(key)
                    .ok_or_else(|| {
                        Error::InvalidTranscript(format!("Missing {} header '{}'", context, key))
                    })?
                    .value
                    .as_str();

                if actual != value {
                    return Err(Error::InvalidTranscript(format!(
                        "Expected {} header '{}' to be '{}', got '{}'",
                        context, key, value, actual
                    )));
                }
            }
            FieldAssertion::BodyFieldEquals { key, value } => {
                let actual = body.get(key).ok_or_else(|| {
                    Error::InvalidTranscript(format!("Missing {} body field '{}'", context, key))
                })?;

                Self::validate_value(value, actual, context, key)?;
            }
        }
        Ok(())
    }

    fn validate_value(
        expected: &ExpectedValue,
        actual: &RangedValue,
        context: &str,
        key: &str,
    ) -> Result<(), Error> {
        match (expected, actual) {
            (ExpectedValue::Null, RangedValue::Null) => Ok(()),
            (ExpectedValue::Bool(expected_val), RangedValue::Bool { value, .. }) => {
                if expected_val == value {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be {}, got {}",
                        context, key, expected_val, value
                    )))
                }
            }
            (ExpectedValue::Number(expected_val), RangedValue::Number { value, .. }) => {
                if (expected_val - value).abs() < f64::EPSILON {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be {}, got {}",
                        context, key, expected_val, value
                    )))
                }
            }
            (ExpectedValue::String(expected_val), RangedValue::String { value, .. }) => {
                if expected_val == value {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be '{}', got '{}'",
                        context, key, expected_val, value
                    )))
                }
            }
            _ => Err(Error::InvalidTranscript(format!(
                "Type mismatch for {} body field '{}'",
                context, key
            ))),
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
