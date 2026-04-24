use std::{ops::Range, path::Path, sync::Arc};

use async_compat::Compat;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tlsnotary::{
    CertificateDer, Direction, RootCertStore, SmolRuntime, TlsCommitProtocolConfig,
    TranscriptCommitment, Verifier, VerifierConfig, VerifierOutput,
};
use tracing::info;

use super::{
    MAX_RECV_DATA, MAX_SENT_DATA,
    error::{ConfigError, ProtocolError, ProvingRequestError},
};
use crate::tls::{TestTlsConfig, get_or_create_test_tls_config};

const MAX_FRAME_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum VerificationOutcome {
    #[serde(rename = "success")]
    Success {
        server_name: String,
        commitment_count: usize,
        message: String,
    },
    #[serde(rename = "failure")]
    Failure {
        server_name: String,
        message: String,
    },
}

impl VerificationOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    pub fn server_name(&self) -> &str {
        match self {
            Self::Success { server_name, .. } | Self::Failure { server_name, .. } => server_name,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Success { message, .. } | Self::Failure { message, .. } => message,
        }
    }

    pub async fn read_from<IO>(io: &mut IO) -> Result<Self, ProtocolError>
    where
        IO: AsyncRead + Unpin + Send,
    {
        read_json_frame(io).await
    }

    pub async fn write_to<IO>(&self, io: &mut IO) -> Result<(), ProtocolError>
    where
        IO: AsyncWrite + Unpin + Send,
    {
        write_json_frame(io, self).await
    }
}

pub async fn run_notarize_stream<IO>(stream: IO) -> Result<(), ProtocolError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut io, output) = Verifier::new(Arc::new(SmolRuntime), create_verifier_config()?)
        .verify(
            Compat::new(stream),
            |protocol| validate_protocol_config(protocol).map_err(|e| e.to_string()),
            |server_identity, reveal_present| {
                validate_proving_request(server_identity, reveal_present).map_err(|e| e.to_string())
            },
        )
        .await?;

    log_verifier_output(&output)?;
    let outcome = VerificationOutcome::Success {
        server_name: output.server_name.clone(),
        commitment_count: output.transcript_commitments.len(),
        message: "Attestation-only flow completed".into(),
    };
    send_verification_outcome_and_close(&mut io, &outcome).await?;
    Ok(())
}

fn create_verifier_config() -> Result<VerifierConfig, ProtocolError> {
    let TestTlsConfig { cert_bytes, .. } = get_or_create_test_tls_config(
        Path::new(".data/tls/server-cert.pem"),
        Path::new(".data/tls/server-key.pem"),
    )?;

    Ok(VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()?)
}

async fn read_json_frame<IO, T>(io: &mut IO) -> Result<T, ProtocolError>
where
    IO: AsyncRead + Unpin + Send,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let frame_len = usize::try_from(u32::from_be_bytes(len_buf))
        .map_err(|_| ProtocolError::FrameTooLarge(u32::from_be_bytes(len_buf) as usize))?;
    if frame_len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(frame_len));
    }

    let mut payload = vec![0u8; frame_len];
    io.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

async fn write_json_frame<IO, T>(io: &mut IO, value: &T) -> Result<(), ProtocolError>
where
    IO: AsyncWrite + Unpin + Send,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    let len_u32 =
        u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }

    io.write_all(&len_u32.to_be_bytes()).await?;
    io.write_all(&payload).await?;
    io.flush().await?;
    Ok(())
}

async fn send_verification_outcome_and_close<IO>(
    io: &mut IO,
    outcome: &VerificationOutcome,
) -> Result<(), ProtocolError>
where
    IO: AsyncWrite + Unpin + Send,
{
    info!(
        success = outcome.is_success(),
        "Sending verification outcome"
    );
    outcome.write_to(io).await?;
    io.close().await?;
    Ok(())
}

fn validate_protocol_config(protocol: &TlsCommitProtocolConfig) -> Result<(), ConfigError> {
    let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = protocol else {
        return Err(ConfigError::UnsupportedProtocol);
    };

    if mpc_tls_config.max_sent_data() > MAX_SENT_DATA {
        return Err(ConfigError::BoundExceeded {
            field: "max_sent_data",
            limit: MAX_SENT_DATA,
            actual: mpc_tls_config.max_sent_data(),
        });
    }

    if mpc_tls_config.max_recv_data() > MAX_RECV_DATA {
        return Err(ConfigError::BoundExceeded {
            field: "max_recv_data",
            limit: MAX_RECV_DATA,
            actual: mpc_tls_config.max_recv_data(),
        });
    }

    Ok(())
}

fn validate_proving_request(
    server_identity_revealed: bool,
    reveal_payload_present: bool,
) -> Result<(), ProvingRequestError> {
    if !server_identity_revealed {
        return Err(ProvingRequestError::MissingServerIdentity);
    }

    if !reveal_payload_present {
        return Err(ProvingRequestError::MissingRevealPayload);
    }

    Ok(())
}

fn log_verifier_output(output: &VerifierOutput) -> Result<(), ProtocolError> {
    let request = std::str::from_utf8(output.transcript.sent_unsafe())?;
    let response = std::str::from_utf8(output.transcript.received_unsafe())?;

    let request_mask = build_commitment_mask(
        &output.transcript_commitments,
        Direction::Sent,
        request.len(),
    );
    let response_mask = build_commitment_mask(
        &output.transcript_commitments,
        Direction::Received,
        response.len(),
    );

    info!(
        server_name = %output.server_name,
        request_len = request.len(),
        response_len = response.len(),
        commitment_count = output.transcript_commitments.len(),
        "Received notarization transcript from prover"
    );
    info!(
        "Verifier redacted request text (legend: x redacted byte, # committed byte):\n{}",
        render_verifier_view(request, &request_mask)
    );
    info!(
        "Verifier redacted response text (legend: x redacted byte, # committed byte):\n{}",
        render_verifier_view(response, &response_mask)
    );

    info!(parsed_request = ?output.parsed_request, "Parsed notarized request");
    log_redacted_request_details(&output.parsed_request, request)?;
    info!(parsed_response = ?output.parsed_response, "Parsed notarized response");
    log_redacted_response_details(&output.parsed_response, response)?;

    for (index, commitment) in output.transcript_commitments.iter().enumerate() {
        match commitment {
            TranscriptCommitment::Hash(hash) => {
                let (range_start, range_end) =
                    hash.idx.min().zip(hash.idx.end()).unwrap_or_default();
                info!(
                    commitment_index = index,
                    commitment_kind = "hash",
                    commitment_direction = ?hash.direction,
                    commitment_alg = ?hash.hash.alg,
                    commitment_hash = ?hash.hash.value,
                    range_start,
                    range_end,
                    "Transcript commitment details"
                );
            }
            other => info!(
                commitment_index = index,
                commitment = ?other,
                "Transcript commitment details"
            ),
        }
    }

    Ok(())
}

fn build_commitment_mask(
    transcript_commitments: &[TranscriptCommitment],
    direction: Direction,
    transcript_len: usize,
) -> Vec<bool> {
    let mut mask = vec![false; transcript_len];
    transcript_commitments
        .iter()
        .filter_map(|c| match c {
            TranscriptCommitment::Hash(hash) if hash.direction == direction => Some(hash),
            _ => None,
        })
        .filter_map(|hash| hash.idx.min().zip(hash.idx.end()))
        .for_each(|(start, end)| {
            let start = start.min(transcript_len);
            let end = end.min(transcript_len);
            mask.get_mut(start..end)
                .into_iter()
                .flatten()
                .for_each(|b| *b = true);
        });
    mask
}

fn render_verifier_view(transcript: &str, commit_mask: &[bool]) -> String {
    let bytes = transcript.as_bytes();
    let max_len = bytes.len().min(commit_mask.len());

    let mut out = bytes.iter().zip(commit_mask.iter()).take(max_len).fold(
        String::new(),
        |mut out, (&byte, &committed)| {
            if committed {
                out.push('#');
            } else if byte == 0 {
                out.push('x');
            } else {
                match byte {
                    b'\r' | b'\n' => {
                        if !out.ends_with('\n') {
                            out.push('\n');
                        }
                    }
                    b'\t' => out.push('\t'),
                    0x20..=0x7e => out.push(char::from(byte)),
                    _ => out.push_str(&format!("\\x{byte:02X}")),
                }
            }
            out
        },
    );

    if commit_mask.len() > bytes.len() {
        out.push_str(&"#".repeat(commit_mask.len() - bytes.len()));
    }

    out
}

fn sanitize_log_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let mut count = 1usize;
                while matches!(chars.peek(), Some(next) if *next == c) {
                    count += 1;
                    chars.next();
                }

                if c == '\0' {
                    if count == 1 {
                        out.push_str("\\0");
                    } else {
                        out.push_str(&format!("\\0x{count}"));
                    }
                } else if count == 1 {
                    out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
                } else {
                    out.push_str(&format!("\\u{{{:04X}}}x{count}", u32::from(c)));
                }
            }
            c => out.push(c),
        }
    }

    out
}

fn preview_text_range(
    source: &str,
    range: &Range<usize>,
    label: impl Into<String>,
) -> Result<String, ProtocolError> {
    source
        .get(range.clone())
        .map(sanitize_log_text)
        .ok_or_else(|| ProtocolError::InvalidTranscriptRange {
            label: label.into(),
            start: range.start,
            end: range.end,
            len: source.len(),
        })
}

fn log_redacted_request_details(
    parsed_request: &tlsnotary::parser::redacted::Request,
    request: &str,
) -> Result<(), ProtocolError> {
    for (header_key, headers) in &parsed_request.headers {
        for (idx, header) in headers.iter().enumerate() {
            let value_preview = match &header.value {
                Some(range) => preview_text_range(
                    request,
                    range,
                    format!("request header '{header_key}' value"),
                )?,
                None => String::from("<redacted>"),
            };
            info!(
                direction = "request",
                item = "header",
                header_key = %header_key,
                header_index = idx,
                name_range_start = header.name.start,
                name_range_end = header.name.end,
                value_revealed = header.value.is_some(),
                value_range_start = header.value.as_ref().map_or(0, |range| range.start),
                value_range_end = header.value.as_ref().map_or(0, |range| range.end),
                name_preview = %preview_text_range(
                    request,
                    &header.name,
                    format!("request header '{header_key}' name"),
                )?,
                value_preview = %value_preview,
                "Parsed transcript request field"
            );
        }
    }

    for (keypath, body_field) in &parsed_request.body {
        match body_field {
            tlsnotary::parser::redacted::Body::KeyValue { key, value } => {
                let value_preview = match value {
                    Some(range) => preview_text_range(
                        request,
                        range,
                        format!("request body field '{keypath}' value"),
                    )?,
                    None => String::from("<redacted>"),
                };
                info!(
                    direction = "request",
                    item = "body-key-value",
                    keypath = %keypath,
                    key_range_start = key.start,
                    key_range_end = key.end,
                    value_revealed = value.is_some(),
                    value_range_start = value.as_ref().map_or(0, |range| range.start),
                    value_range_end = value.as_ref().map_or(0, |range| range.end),
                    key_preview = %preview_text_range(
                        request,
                        key,
                        format!("request body field '{keypath}' key"),
                    )?,
                    value_preview = %value_preview,
                    "Parsed transcript request field"
                );
            }
            tlsnotary::parser::redacted::Body::Value(range) => {
                info!(
                    direction = "request",
                    item = "body-value",
                    keypath = %keypath,
                    value_range_start = range.start,
                    value_range_end = range.end,
                    value_preview = %preview_text_range(
                        request,
                        range,
                        format!("request body field '{keypath}'"),
                    )?,
                    "Parsed transcript request field"
                );
            }
        }
    }

    Ok(())
}

fn log_redacted_response_details(
    parsed_response: &tlsnotary::parser::redacted::Response,
    response: &str,
) -> Result<(), ProtocolError> {
    for (header_key, headers) in &parsed_response.headers {
        for (idx, header) in headers.iter().enumerate() {
            let value_preview = match &header.value {
                Some(range) => preview_text_range(
                    response,
                    range,
                    format!("response header '{header_key}' value"),
                )?,
                None => String::from("<redacted>"),
            };
            info!(
                direction = "response",
                item = "header",
                header_key = %header_key,
                header_index = idx,
                name_range_start = header.name.start,
                name_range_end = header.name.end,
                value_revealed = header.value.is_some(),
                value_range_start = header.value.as_ref().map_or(0, |range| range.start),
                value_range_end = header.value.as_ref().map_or(0, |range| range.end),
                name_preview = %preview_text_range(
                    response,
                    &header.name,
                    format!("response header '{header_key}' name"),
                )?,
                value_preview = %value_preview,
                "Parsed transcript response field"
            );
        }
    }

    for (keypath, body_field) in &parsed_response.body {
        match body_field {
            tlsnotary::parser::redacted::Body::KeyValue { key, value } => {
                let value_preview = match value {
                    Some(range) => preview_text_range(
                        response,
                        range,
                        format!("response body field '{keypath}' value"),
                    )?,
                    None => String::from("<redacted>"),
                };
                info!(
                    direction = "response",
                    item = "body-key-value",
                    keypath = %keypath,
                    key_range_start = key.start,
                    key_range_end = key.end,
                    value_revealed = value.is_some(),
                    value_range_start = value.as_ref().map_or(0, |range| range.start),
                    value_range_end = value.as_ref().map_or(0, |range| range.end),
                    key_preview = %preview_text_range(
                        response,
                        key,
                        format!("response body field '{keypath}' key"),
                    )?,
                    value_preview = %value_preview,
                    "Parsed transcript response field"
                );
            }
            tlsnotary::parser::redacted::Body::Value(range) => {
                info!(
                    direction = "response",
                    item = "body-value",
                    keypath = %keypath,
                    value_range_start = range.start,
                    value_range_end = range.end,
                    value_preview = %preview_text_range(
                        response,
                        range,
                        format!("response body field '{keypath}'"),
                    )?,
                    "Parsed transcript response field"
                );
            }
        }
    }

    Ok(())
}
