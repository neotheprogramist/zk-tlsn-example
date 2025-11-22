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
        context: &str,
    ) -> Result<(), Error> {
        match assertion {
            FieldAssertion::HeaderEquals { key, value } => {
                let key_lower = key.to_lowercase();
                let headers_list = headers.get(&key_lower).ok_or_else(|| {
                    Error::InvalidTranscript(format!("Missing {} header '{}'", context, key))
                })?;

                // Get the first header value
                let header = headers_list.first().ok_or_else(|| {
                    Error::InvalidTranscript(format!("Missing {} header '{}'", context, key))
                })?;

                if let Some(value_range) = &header.value {
                    let actual = std::str::from_utf8(&data[value_range.clone()]).map_err(|_| {
                        Error::InvalidTranscript("Invalid UTF-8 in header value".to_string())
                    })?;

                    if actual != value {
                        return Err(Error::InvalidTranscript(format!(
                            "Expected {} header '{}' to be '{}', got '{}'",
                            context, key, value, actual
                        )));
                    }
                } else {
                    return Err(Error::InvalidTranscript(format!(
                        "Expected {} header '{}' to have value '{}', but it has no value",
                        context, key, value
                    )));
                }
            }
            FieldAssertion::BodyFieldEquals { key, value } => {
                let body_field = body.get(key).ok_or_else(|| {
                    Error::InvalidTranscript(format!("Missing {} body field '{}'", context, key))
                })?;

                Self::validate_value(value, body_field, data, context, key)?;
            }
        }
        Ok(())
    }

    fn validate_value(
        expected: &ExpectedValue,
        body_field: &parser::redacted::Body,
        data: &[u8],
        context: &str,
        key: &str,
    ) -> Result<(), Error> {
        let value_range = match body_field {
            parser::redacted::Body::KeyValue { value, .. } => value.as_ref(),
            parser::redacted::Body::Value(range) => Some(range),
        }
        .ok_or_else(|| {
            Error::InvalidTranscript(format!(
                "Missing value for {} body field '{}'",
                context, key
            ))
        })?;

        let actual_str = std::str::from_utf8(&data[value_range.clone()])
            .map_err(|_| Error::InvalidTranscript("Invalid UTF-8 in body value".to_string()))?;

        match expected {
            ExpectedValue::Null => {
                if actual_str == "null" {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be null, got '{}'",
                        context, key, actual_str
                    )))
                }
            }
            ExpectedValue::Bool(expected_val) => {
                let actual_bool = actual_str.parse::<bool>().map_err(|_| {
                    Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be a boolean, got '{}'",
                        context, key, actual_str
                    ))
                })?;

                if expected_val == &actual_bool {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be {}, got {}",
                        context, key, expected_val, actual_bool
                    )))
                }
            }
            ExpectedValue::Number(expected_val) => {
                let actual_num = actual_str.parse::<f64>().map_err(|_| {
                    Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be a number, got '{}'",
                        context, key, actual_str
                    ))
                })?;

                if (expected_val - actual_num).abs() < f64::EPSILON {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be {}, got {}",
                        context, key, expected_val, actual_num
                    )))
                }
            }
            ExpectedValue::String(expected_val) => {
                if expected_val == actual_str {
                    Ok(())
                } else {
                    Err(Error::InvalidTranscript(format!(
                        "Expected {} body field '{}' to be '{}', got '{}'",
                        context, key, expected_val, actual_str
                    )))
                }
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
