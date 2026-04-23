use std::{ops::Range, path::Path, str::FromStr};

use async_compat::Compat;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tlsnotary::{
    CertificateDer, Direction, RootCertStore, Session, TlsCommitProtocolConfig,
    TranscriptCommitment, VerifierConfig,
};
use tracing::{info, instrument, warn};

use super::{
    MAX_RECV_DATA, MAX_SENT_DATA,
    error::{ConfigError, ProtocolError, ProvingRequestError},
};
use crate::testing::{TestTlsConfig, get_or_create_test_tls_config};

const MAX_FRAME_BYTES: usize = 1 << 20;

struct StepProgress {
    current: usize,
    total: usize,
}

impl StepProgress {
    fn new(total: usize) -> Self {
        Self { current: 0, total }
    }

    fn tick(&mut self, stage: &str) {
        self.current = (self.current + 1).min(self.total);
        let width = 20usize;
        let filled = (self.current * width) / self.total.max(1);
        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            "░".repeat(width.saturating_sub(filled))
        );
        let percent = (self.current * 100) / self.total.max(1);
        info!(
            stage = %stage,
            step = self.current,
            total_steps = self.total,
            percent,
            progress_bar = %bar,
            "Verifier stream progress"
        );
    }
}

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

#[derive(Debug, Clone)]
struct NotarizedTranscript {
    server_name: String,
    request: String,
    response: String,
    transcript_commitments: Vec<TranscriptCommitment>,
}

#[instrument(skip(stream), fields(phase = "notarize"))]
pub async fn run_notarize_stream<IO>(stream: IO) -> Result<(), ProtocolError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut progress = StepProgress::new(4);
    progress.tick("starting pipeline");
    let (mut io, notarized_transcript) = run_notarization(stream).await?;
    progress.tick("notarization finished");
    log_notarized_transcript(&notarized_transcript)?;
    info!(
        server_name = %notarized_transcript.server_name,
        commitments = notarized_transcript.transcript_commitments.len(),
        "Notarization complete"
    );

    let outcome = VerificationOutcome::Success {
        server_name: notarized_transcript.server_name.clone(),
        commitment_count: notarized_transcript.transcript_commitments.len(),
        message: "Attestation-only flow completed".into(),
    };
    send_verification_outcome_and_close(&mut io, &outcome).await?;
    progress.tick("sent verification result");
    progress.tick("stream closed");
    Ok(())
}

#[instrument(skip(stream), fields(phase = "notarize:mpc"))]
async fn run_notarization<IO>(
    stream: IO,
) -> Result<(Compat<IO>, NotarizedTranscript), ProtocolError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(Compat::new(stream));
    let (driver, mut handle) = session.split();
    let driver_task = smol::spawn(driver);

    let verifier_config = create_verifier_config()?;
    info!("Created verifier configuration");
    let verifier = handle.new_verifier(verifier_config)?;
    info!("Verifier session created");
    let verifier = verifier.commit().await?;
    info!("Verifier committed protocol proposal");

    if let Err(error) = validate_protocol_config(verifier.request().protocol()) {
        verifier.reject(Some(&error.to_string())).await?;
        warn!(reason = %error, "Rejected prover protocol configuration");
        return Err(error.into());
    }
    info!("Accepted prover protocol configuration");

    let verifier = verifier.accept().await?.run().await?;
    info!("Finished MPC-TLS run");
    let verifier = verifier.verify().await?;
    info!("Started verification phase");

    if let Err(error) = validate_proving_request(
        verifier.request().server_identity(),
        verifier.request().reveal().is_some(),
    ) {
        let verifier = verifier.reject(Some(&error.to_string())).await?;
        verifier.close().await?;
        warn!(reason = %error, "Rejected proving request");
        return Err(error.into());
    }

    let (output, verifier) = verifier.accept().await?;
    info!("Accepted verifier output from prover");
    verifier.close().await?;

    handle.close();
    let io = driver_task.await?;

    let server_name = output
        .server_name
        .ok_or(ProtocolError::MissingField("server_name"))?
        .to_string();
    let transcript = output
        .transcript
        .ok_or(ProtocolError::MissingField("transcript"))?;
    let request = String::from_utf8(transcript.sent_unsafe().to_vec())?;
    let response = String::from_utf8(transcript.received_unsafe().to_vec())?;

    Ok((
        io,
        NotarizedTranscript {
            server_name,
            request,
            response,
            transcript_commitments: output.transcript_commitments,
        },
    ))
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
    let raw_len = u32::from_be_bytes(len_buf);
    let frame_len = usize::try_from(raw_len)
        .ok()
        .ok_or(ProtocolError::FrameTooLarge(raw_len as usize))?;
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
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }

    let len_u32 = u32::try_from(payload.len())
        .ok()
        .ok_or(ProtocolError::FrameTooLarge(payload.len()))?;
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
    outcome
        .write_to(io)
        .await
        .inspect_err(|e| warn!(error = %e, "Failed sending verification outcome"))?;
    io.close().await?;
    Ok(())
}

fn validate_protocol_config(protocol: &TlsCommitProtocolConfig) -> Result<(), ConfigError> {
    let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = protocol else {
        return Err(ConfigError::UnsupportedProtocol);
    };

    if mpc_tls_config.max_sent_data() > MAX_SENT_DATA {
        return Err(ConfigError::MaxSentDataTooLarge {
            limit: MAX_SENT_DATA,
            actual: mpc_tls_config.max_sent_data(),
        });
    }

    if mpc_tls_config.max_recv_data() > MAX_RECV_DATA {
        return Err(ConfigError::MaxRecvDataTooLarge {
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

fn log_notarized_transcript(
    notarized_transcript: &NotarizedTranscript,
) -> Result<(), ProtocolError> {
    let request_commit_mask = build_commitment_mask(
        &notarized_transcript.transcript_commitments,
        Direction::Sent,
        notarized_transcript.request.len(),
    );
    let response_commit_mask = build_commitment_mask(
        &notarized_transcript.transcript_commitments,
        Direction::Received,
        notarized_transcript.response.len(),
    );

    info!(
        server_name = %notarized_transcript.server_name,
        request_len = notarized_transcript.request.len(),
        response_len = notarized_transcript.response.len(),
        commitment_count = notarized_transcript.transcript_commitments.len(),
        "Received notarization transcript from prover"
    );
    let request_view = render_verifier_view(&notarized_transcript.request, &request_commit_mask);
    let response_view = render_verifier_view(&notarized_transcript.response, &response_commit_mask);
    info!(
        "Verifier redacted request text (legend: x redacted byte, # committed byte):\n{}",
        request_view
    );
    info!(
        "Verifier redacted response text (legend: x redacted byte, # committed byte):\n{}",
        response_view
    );

    let parsed_request =
        tlsnotary::parser::redacted::Request::from_str(&notarized_transcript.request)?;
    info!(parsed_request = ?parsed_request, "Parsed notarized request");
    log_redacted_request_details(&parsed_request, &notarized_transcript.request)?;

    let parsed_response =
        tlsnotary::parser::redacted::Response::from_str(&notarized_transcript.response)?;
    info!(parsed_response = ?parsed_response, "Parsed notarized response");
    log_redacted_response_details(&parsed_response, &notarized_transcript.response)?;

    for (index, commitment) in notarized_transcript
        .transcript_commitments
        .iter()
        .enumerate()
    {
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
        let hidden_tail = commit_mask.len() - bytes.len();
        out.push_str(&"#".repeat(hidden_tail));
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
