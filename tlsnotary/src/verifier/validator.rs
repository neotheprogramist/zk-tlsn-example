use std::collections::HashMap;

use tlsn::hash::HashAlgId;

use super::VerifierOutput;
use crate::error::{Error, TranscriptError};

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
        headers: &HashMap<String, Vec<crate::parser::redacted::Header>>,
        body: &HashMap<String, crate::parser::redacted::Body>,
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
        field: &crate::parser::redacted::Body,
        data: &[u8],
        ctx: &'static str,
        key: &str,
    ) -> Result<(), Error> {
        let range = match field {
            crate::parser::redacted::Body::KeyValue { value, .. } => value.as_ref(),
            crate::parser::redacted::Body::Value(r) => Some(r),
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
