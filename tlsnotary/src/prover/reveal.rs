//! Selective disclosure configuration for HTTP requests and responses.

use parser::{
    HttpBody, HttpHeader, HttpMessage,
    standard::{Request, Response},
};
use tlsn::{prover::ProveConfigBuilder, transcript::TranscriptCommitConfigBuilder};

use crate::error::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevealConfig {
    pub reveal_headers: Vec<String>,
    pub commit_headers: Vec<String>,
    pub reveal_body_keypaths: Vec<String>,
    pub commit_body_keypaths: Vec<String>,
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

    // Reveal request line (method, URL, protocol version)
    let request_line_range = parsed_request.method.start..parsed_request.protocol_version.end + 1;
    builder.reveal_sent(&request_line_range)?;

    if !config.reveal_headers.is_empty() {
        for header_name in &config.reveal_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_request.headers().get(&header_name_lower) {
                for header in headers {
                    builder.reveal_sent(&header.full_range())?;
                }
            }
        }
    }

    if !config.commit_headers.is_empty() {
        for header_name in &config.commit_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_request.headers().get(&header_name_lower) {
                for header in headers {
                    transcript_commitment_builder.commit_sent(&header.full_range())?;
                }
            }
        }
    }

    if !config.reveal_body_keypaths.is_empty() {
        for keypath in &config.reveal_body_keypaths {
            if let Some(body_field) = parsed_request.body().get(keypath) {
                builder.reveal_sent(&body_field.full_pair_range())?;
            }
        }
    }

    if !config.commit_body_keypaths.is_empty() {
        for keypath in &config.commit_body_keypaths {
            if let Some(body_field) = parsed_request.body().get(keypath) {
                transcript_commitment_builder.commit_sent(&body_field.full_pair_range())?;
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

    // Reveal status line (protocol version, status code, status)
    let status_line_range = parsed_response.protocol_version.start..parsed_response.status.end + 1;
    builder.reveal_recv(&status_line_range)?;

    if !config.reveal_headers.is_empty() {
        for header_name in &config.reveal_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_response.headers().get(&header_name_lower) {
                for header in headers {
                    builder.reveal_recv(&header.full_range())?;
                }
            }
        }
    }

    if !config.commit_headers.is_empty() {
        for header_name in &config.commit_headers {
            let header_name_lower = header_name.to_lowercase();
            if let Some(headers) = parsed_response.headers().get(&header_name_lower) {
                for header in headers {
                    transcript_commitment_builder.commit_recv(&header.full_range())?;
                }
            }
        }
    }

    if !config.reveal_body_keypaths.is_empty() {
        for keypath in &config.reveal_body_keypaths {
            if let Some(body_field) = parsed_response.body().get(keypath) {
                builder.reveal_recv(&body_field.full_pair_range())?;
            }
        }
    }

    if !config.commit_body_keypaths.is_empty() {
        for keypath in &config.commit_body_keypaths {
            if let Some(body_field) = parsed_response.body().get(keypath) {
                transcript_commitment_builder.commit_recv(&body_field.full_pair_range())?;
            }
        }
    }

    Ok(())
}
