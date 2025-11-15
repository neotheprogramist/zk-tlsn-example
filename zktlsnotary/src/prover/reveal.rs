use parser::{BodySearchable, HeaderSearchable, RequestParser, ResponseParser};
use tlsn::{prover::ProveConfigBuilder, transcript::TranscriptCommitConfigBuilder};

use crate::error::ZkTlsNotaryError;

#[derive(Debug, Clone, Default)]
pub struct RevealConfig {
    pub reveal_headers: Vec<String>,
    pub commit_headers: Vec<String>,
    pub reveal_body_keypaths: Vec<String>,
    pub commit_body_keypaths: Vec<String>,
}

pub fn reveal_request(
    request: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
    config: &RevealConfig,
) -> Result<(), ZkTlsNotaryError> {
    if config.reveal_headers.is_empty() && config.reveal_body_keypaths.is_empty() {
        builder.reveal_sent(&(0..request.len()))?;
        return Ok(());
    }

    let raw_request_str = String::from_utf8(request.to_vec())
        .map_err(|_| ZkTlsNotaryError::InvalidTranscript("Request is not valid UTF-8".into()))?;

    let parsed_request = RequestParser::parse_request(&raw_request_str)?;

    let request_line_range = parsed_request.get_request_line_range();
    builder.reveal_sent(&request_line_range)?;

    if !config.reveal_headers.is_empty() {
        let header_strs: Vec<&str> = config.reveal_headers.iter().map(|s| s.as_str()).collect();
        let header_ranges = parsed_request.get_header_ranges(&header_strs)?;
        for range in header_ranges {
            builder.reveal_sent(&range)?;
        }
    }

    if !config.commit_headers.is_empty() {
        let header_strs: Vec<&str> = config.commit_headers.iter().map(|s| s.as_str()).collect();
        let header_ranges = parsed_request.get_header_ranges(&header_strs)?;
        for range in header_ranges {
            transcript_commitment_builder.commit_sent(&range)?;
        }
    }

    if !config.reveal_body_keypaths.is_empty() {
        let keypath_strs: Vec<&str> = config
            .reveal_body_keypaths
            .iter()
            .map(|s| s.as_str())
            .collect();
        let body_ranges = parsed_request.get_body_keypaths_ranges(&keypath_strs)?;
        for range in body_ranges {
            builder.reveal_sent(&range)?;
        }
    }

    if !config.commit_body_keypaths.is_empty() {
        let keypath_strs: Vec<&str> = config
            .commit_body_keypaths
            .iter()
            .map(|s| s.as_str())
            .collect();
        let commit_ranges = parsed_request.get_body_keypaths_ranges(&keypath_strs)?;
        for range in commit_ranges {
            transcript_commitment_builder.commit_sent(&range)?;
        }
    }

    Ok(())
}

pub fn reveal_response(
    response: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
    config: &RevealConfig,
) -> Result<(), ZkTlsNotaryError> {
    let raw_response_str = String::from_utf8(response.to_vec())
        .map_err(|_| ZkTlsNotaryError::InvalidTranscript("Response is not valid UTF-8".into()))?;

    let parsed_response = ResponseParser::parse_response(&raw_response_str)?;

    let status_line_range = parsed_response.get_status_line_range();
    builder.reveal_recv(&status_line_range)?;

    if !config.reveal_headers.is_empty() {
        let header_strs: Vec<&str> = config.reveal_headers.iter().map(|s| s.as_str()).collect();
        let header_ranges = parsed_response.get_header_ranges(&header_strs)?;
        for range in header_ranges {
            builder.reveal_recv(&range)?;
        }
    }

    if !config.commit_headers.is_empty() {
        let header_strs: Vec<&str> = config.commit_headers.iter().map(|s| s.as_str()).collect();
        let header_ranges = parsed_response.get_header_ranges(&header_strs)?;
        for range in header_ranges {
            transcript_commitment_builder.commit_recv(&range)?;
        }
    }

    if !config.reveal_body_keypaths.is_empty() {
        let keypath_strs: Vec<&str> = config
            .reveal_body_keypaths
            .iter()
            .map(|s| s.as_str())
            .collect();
        let body_ranges = parsed_response.get_body_keypaths_ranges(&keypath_strs)?;
        for range in body_ranges {
            builder.reveal_recv(&range)?;
        }
    }

    if !config.commit_body_keypaths.is_empty() {
        let keypath_strs: Vec<&str> = config
            .commit_body_keypaths
            .iter()
            .map(|s| s.as_str())
            .collect();
        let commit_ranges = parsed_response.get_body_keypaths_ranges(&keypath_strs)?;
        for range in commit_ranges {
            transcript_commitment_builder.commit_recv(&range)?;
        }
    }

    Ok(())
}
