use parser::{
    HttpMessage, JsonFieldRangeExt,
    standard::{Body, Request, Response},
};
use tlsn::{prover::ProveConfigBuilder, transcript::TranscriptCommitConfigBuilder};

use crate::error::Error;

fn calculate_padded_range(
    value: &std::ops::Range<usize>,
    commitment_length: usize,
) -> std::ops::Range<usize> {
    let value_len = value.end - value.start;

    if value_len > commitment_length {
        tracing::warn!(
            "Value length {} exceeds commitment length {}, using exact value",
            value_len,
            commitment_length
        );
        return value.clone();
    }

    value.start..(value.start + commitment_length)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyFieldConfig {
    Quoted(String),
    Unquoted(String),
    UnquotedPadded(String, usize),
}

impl BodyFieldConfig {
    fn keypath(&self) -> &str {
        match self {
            Self::Quoted(s) | Self::Unquoted(s) | Self::UnquotedPadded(s, _) => s,
        }
    }

    fn get_range(&self, body_field: &Body) -> std::ops::Range<usize> {
        match (self, body_field) {
            (Self::Quoted(_), Body::KeyValue { key, value }) => key.full_pair_quoted(value),
            (Self::Unquoted(_), Body::KeyValue { key, value }) => key.full_pair_unquoted(value),
            (Self::UnquotedPadded(_, padding_len), Body::KeyValue { key: _, value }) => {
                Self::get_padded_range(value, *padding_len)
            }
            (_, Body::Value(range)) => range.clone(),
        }
    }

    /// Creates a fixed-length commitment range for a value
    fn get_padded_range(
        value: &std::ops::Range<usize>,
        commitment_length: usize,
    ) -> std::ops::Range<usize> {
        calculate_padded_range(value, commitment_length)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValueCommitConfig {
    pub keypath: String,
    pub commitment_length: Option<usize>,
}

impl KeyValueCommitConfig {
    #[must_use]
    pub fn new(keypath: String) -> Self {
        Self {
            keypath,
            commitment_length: None,
        }
    }

    #[must_use]
    pub fn with_padding(keypath: String, commitment_length: usize) -> Self {
        Self {
            keypath,
            commitment_length: Some(commitment_length),
        }
    }

    fn get_value_range(&self, value: &std::ops::Range<usize>) -> std::ops::Range<usize> {
        self.commitment_length
            .map_or_else(|| value.clone(), |len| calculate_padded_range(value, len))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevealConfig {
    pub reveal_headers: Vec<String>,
    pub commit_headers: Vec<String>,
    pub reveal_body_keypaths: Vec<BodyFieldConfig>,
    pub commit_body_keypaths: Vec<BodyFieldConfig>,
    pub reveal_key_commit_value_keypaths: Vec<KeyValueCommitConfig>,
}

impl RevealConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn reveal_all() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn commit_all() -> Self {
        Self {
            reveal_headers: vec![],
            commit_headers: vec![],
            reveal_body_keypaths: vec![],
            commit_body_keypaths: vec![],
            reveal_key_commit_value_keypaths: vec![],
        }
    }
}

/// # Errors
///
/// Returns error if request is not UTF-8, parsing fails, or field lookup fails.
pub fn reveal_request(
    request: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
    config: &RevealConfig,
) -> Result<(), Error> {
    if config.reveal_headers.is_empty() && config.reveal_body_keypaths.is_empty() {
        builder.reveal_sent(&(0..request.len()))?;
        return Ok(());
    }

    let raw_request_str = String::from_utf8(request.to_vec())?;

    let parsed_request: Request = raw_request_str.parse()?;

    let request_line_range =
        parsed_request.method.start..parsed_request.protocol_version.with_newline().end;
    builder.reveal_sent(&request_line_range)?;

    if !config.reveal_headers.is_empty() {
        for header_name in &config.reveal_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_request.headers().get(&header_name_lower) {
                for header in headers {
                    let range = header.name.header_full_range(&header.value);
                    builder.reveal_sent(&range)?;
                }
            }
        }
    }

    if !config.commit_headers.is_empty() {
        for header_name in &config.commit_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_request.headers().get(&header_name_lower) {
                for header in headers {
                    let range = header.name.header_full_range(&header.value);
                    transcript_commitment_builder.commit_sent(&range)?;
                }
            }
        }
    }

    for field_config in &config.reveal_body_keypaths {
        if let Some(body_field) = parsed_request.body().get(field_config.keypath()) {
            builder.reveal_sent(&field_config.get_range(body_field))?;
        }
    }

    for field_config in &config.commit_body_keypaths {
        if let Some(body_field) = parsed_request.body().get(field_config.keypath()) {
            transcript_commitment_builder.commit_sent(&field_config.get_range(body_field))?;
        }
    }

    for kv_config in &config.reveal_key_commit_value_keypaths {
        if let Some(body_field) = parsed_request.body().get(&kv_config.keypath) {
            match body_field {
                Body::KeyValue { key, value } => {
                    builder.reveal_sent(&key.with_quotes_and_colon())?;
                    let value_range = kv_config.get_value_range(value);
                    transcript_commitment_builder.commit_sent(&value_range)?;
                }
                Body::Value(_) => {
                    return Err(Error::InvalidInput(format!(
                        "Expected key-value pair for keypath {}, got standalone value",
                        kv_config.keypath
                    )));
                }
            }
        }
    }

    Ok(())
}

/// # Errors
///
/// Returns error if response is not UTF-8, parsing fails, or field lookup fails.
pub fn reveal_response(
    response: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
    config: &RevealConfig,
) -> Result<(), Error> {
    let raw_response_str = String::from_utf8(response.to_vec())?;
    let parsed_response: Response = raw_response_str.parse()?;

    let status_line_range =
        parsed_response.protocol_version.start..parsed_response.status.with_newline().end;
    builder.reveal_recv(&status_line_range)?;

    if !config.reveal_headers.is_empty() {
        for header_name in &config.reveal_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_response.headers().get(&header_name_lower) {
                for header in headers {
                    let range = header.name.header_full_range(&header.value);
                    builder.reveal_recv(&range)?;
                }
            }
        }
    }

    if !config.commit_headers.is_empty() {
        for header_name in &config.commit_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_response.headers().get(&header_name_lower) {
                for header in headers {
                    let range = header.name.header_full_range(&header.value);
                    transcript_commitment_builder.commit_recv(&range)?;
                }
            }
        }
    }

    for field_config in &config.reveal_body_keypaths {
        if let Some(body_field) = parsed_response.body().get(field_config.keypath()) {
            builder.reveal_recv(&field_config.get_range(body_field))?;
        }
    }

    for field_config in &config.commit_body_keypaths {
        if let Some(body_field) = parsed_response.body().get(field_config.keypath()) {
            transcript_commitment_builder.commit_recv(&field_config.get_range(body_field))?;
        }
    }

    for kv_config in &config.reveal_key_commit_value_keypaths {
        if let Some(body_field) = parsed_response.body().get(&kv_config.keypath) {
            match body_field {
                Body::KeyValue { key, value } => {
                    builder.reveal_recv(&key.with_quotes_and_colon())?;
                    let value_range = kv_config.get_value_range(value);
                    transcript_commitment_builder.commit_recv(&value_range)?;
                }
                Body::Value(_) => {
                    return Err(Error::InvalidInput(format!(
                        "Expected key-value pair for keypath {}, got standalone value",
                        kv_config.keypath
                    )));
                }
            }
        }
    }

    Ok(())
}
