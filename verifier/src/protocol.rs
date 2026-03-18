use std::{collections::HashMap, ops::Range, path::Path, str::FromStr};

use async_compat::Compat;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use shared::{TestTlsConfig, get_or_create_test_tls_config};
use tlsnotary::{
    CertificateDer, Direction, RootCertStore, Session, TlsCommitProtocolConfig,
    TranscriptCommitment, VerifierConfig,
};
use tracing::{debug, info, instrument, warn};
use zktlsn::{
    Proof, SignedTransferTicket, TicketSigner, bind_commitments_to_keys,
    extract_committed_hash_from_proof, extract_transfer_fields_from_proof,
    verify_proof_against_hash,
};

use crate::{MAX_RECV_DATA, MAX_SENT_DATA, errors::ProtocolError};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofMessage {
    pub proof: Proof,
}

impl ProofMessage {
    pub fn new(proof: Proof) -> Self {
        Self { proof }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOutcome {
    pub success: bool,
    pub server_name: String,
    pub verified_fields: Vec<String>,
    pub message: String,
    pub signed_ticket: Option<SignedTransferTicket>,
}

impl VerificationOutcome {
    pub fn success(
        server_name: String,
        verified_fields: Vec<String>,
        message: String,
        signed_ticket: SignedTransferTicket,
    ) -> Self {
        Self {
            success: true,
            server_name,
            verified_fields,
            message,
            signed_ticket: Some(signed_ticket),
        }
    }

    pub fn failure(server_name: String, message: String) -> Self {
        Self {
            success: false,
            server_name,
            verified_fields: Vec::new(),
            message,
            signed_ticket: None,
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

#[instrument(skip(stream), fields(phase = "notarize+verify"))]
pub async fn run_notarize_and_verify_stream<IO>(stream: IO) -> Result<(), ProtocolError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut progress = StepProgress::new(6);
    progress.tick("starting pipeline");
    let (mut io, notarized_transcript) = run_notarization(stream).await?;
    progress.tick("notarization finished");
    log_notarized_transcript(&notarized_transcript)?;
    info!(
        server_name = %notarized_transcript.server_name,
        commitments = notarized_transcript.transcript_commitments.len(),
        "Notarization complete"
    );

    let proof_message = ProofMessage::read_from(&mut io).await?;
    progress.tick("received proof payload");
    info!(
        proof_len = proof_message.proof.proof.len(),
        vk_len = proof_message.proof.verification_key.len(),
        proof_prefix_hex = %hex_preview(&proof_message.proof.proof, 32),
        vk_prefix_hex = %hex_preview(&proof_message.proof.verification_key, 32),
        "Received proof payload"
    );
    debug!(
        proof_bytes = ?proof_message.proof.proof,
        verification_key_bytes = ?proof_message.proof.verification_key,
        "Received full proof payload bytes"
    );

    let (verified_fields, signed_ticket) =
        match verify_proof_message(&notarized_transcript, proof_message) {
            Ok(result) => result,
            Err(error) => {
                warn!(error = %error, "Proof verification failed");
                progress.tick("proof verification finished");
                send_verification_outcome_and_close(
                    &mut io,
                    &VerificationOutcome::failure(
                        notarized_transcript.server_name.clone(),
                        error.to_string(),
                    ),
                )
                .await?;
                progress.tick("sent verification result");
                progress.tick("stream closed");
                return Err(error);
            }
        };
    progress.tick("proof verification finished");

    let verification_outcome = VerificationOutcome::success(
        notarized_transcript.server_name.clone(),
        verified_fields,
        "ZK proof verified successfully".to_string(),
        signed_ticket,
    );
    send_verification_outcome_and_close(&mut io, &verification_outcome).await?;
    progress.tick("sent verification result");
    progress.tick("stream closed");
    Ok(())
}

#[instrument(skip(stream), fields(phase = "notarize"))]
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
    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(tlsnotary::Error::from)?;
    info!("Verifier session created");
    let verifier = verifier.commit().await.map_err(tlsnotary::Error::from)?;
    info!("Verifier committed protocol proposal");

    if let Some(reason) = protocol_rejection_reason(verifier.request().protocol()) {
        verifier
            .reject(Some(reason.as_str()))
            .await
            .map_err(tlsnotary::Error::from)?;
        warn!(reason = %reason, "Rejected prover protocol configuration");
        return Err(ProtocolError::InvalidConfig(reason));
    }
    info!("Accepted prover protocol configuration");

    let verifier = verifier
        .accept()
        .await
        .map_err(tlsnotary::Error::from)?
        .run()
        .await
        .map_err(tlsnotary::Error::from)?;
    info!("Finished MPC-TLS run");
    let verifier = verifier.verify().await.map_err(tlsnotary::Error::from)?;
    info!("Started verification phase");

    if let Some(reason) = proving_request_rejection_reason(
        verifier.request().server_identity(),
        verifier.request().reveal().is_some(),
    ) {
        let verifier = verifier
            .reject(Some(reason.as_str()))
            .await
            .map_err(tlsnotary::Error::from)?;
        verifier.close().await.map_err(tlsnotary::Error::from)?;
        warn!(reason = %reason, "Rejected proving request");
        return Err(ProtocolError::InvalidProvingRequest(reason));
    }

    let (output, verifier) = verifier.accept().await.map_err(tlsnotary::Error::from)?;
    info!("Accepted verifier output from prover");
    verifier.close().await.map_err(tlsnotary::Error::from)?;

    handle.close();
    let io = driver_task.await.map_err(tlsnotary::Error::from)?;

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

fn verify_proof_message(
    notarized_transcript: &NotarizedTranscript,
    proof_message: ProofMessage,
) -> Result<(Vec<String>, SignedTransferTicket), ProtocolError> {
    let parsed_response = parser::redacted::Response::from_str(&notarized_transcript.response)
        .map_err(|error| ProtocolError::ResponseParse(format!("{error:?}")))?;
    let bindings = bind_commitments_to_keys(
        &parsed_response,
        &notarized_transcript.transcript_commitments,
    )
    .map_err(|error| ProtocolError::CommitmentBindingFailed(error.to_string()))?;

    if bindings.is_empty() {
        return Err(ProtocolError::NoCommitmentsFound);
    }

    let proof_committed_hash = extract_committed_hash_from_proof(&proof_message.proof)
        .map_err(|error| ProtocolError::ProofVerificationFailed(error.to_string()))?;
    info!(
        proof_committed_hash = %hex_preview(&proof_committed_hash, proof_committed_hash.len()),
        "Extracted public committed hash from proof"
    );

    info!(parsed_response = ?parsed_response, "Parsed notarized response");
    for (field, binding) in &bindings {
        info!(
            field = %field,
            key_range_start = binding.key_range.start,
            key_range_end = binding.key_range.end,
            commitment_range_start = binding.hash.idx.min().unwrap_or(0),
            commitment_range_end = binding.hash.idx.end().unwrap_or(0),
            commitment_direction = ?binding.hash.direction,
            commitment_alg = ?binding.hash.hash.alg,
            "Bound response field to transcript commitment"
        );
    }

    let (matched_field, expected_hash) =
        select_unique_bound_field_for_hash(&bindings, &proof_committed_hash)?;
    verify_proof_against_hash(&proof_message.proof, &expected_hash)
        .map_err(|error| ProtocolError::ProofVerificationFailed(error.to_string()))?;
    info!(
        field = %matched_field,
        "Proof cryptographically bound to transcript commitment"
    );

    let transfer = extract_transfer_fields_from_proof(&proof_message.proof)
        .map_err(|error| ProtocolError::ProofVerificationFailed(error.to_string()))?;
    let signed_ticket = TicketSigner::from_env_or_default()
        .map_err(|error| ProtocolError::InvalidConfig(error.to_string()))?
        .sign_ticket(transfer.tx_id, transfer.to_user_id, transfer.amount)
        .map_err(|error| ProtocolError::ProofVerificationFailed(error.to_string()))?;

    Ok((vec![matched_field], signed_ticket))
}

fn create_verifier_config() -> Result<VerifierConfig, ProtocolError> {
    let TestTlsConfig { cert_bytes, .. } =
        get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))
            .map_err(|error| ProtocolError::InvalidConfig(error.to_string()))?;

    Ok(VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()
        .map_err(tlsnotary::Error::from)?)
}

async fn read_json_frame<IO, T>(io: &mut IO) -> Result<T, ProtocolError>
where
    IO: AsyncRead + Unpin + Send,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
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

    io.write_all(&(payload.len() as u32).to_be_bytes()).await?;
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
    outcome.write_to(io).await?;
    io.close().await?;
    Ok(())
}

fn protocol_rejection_reason(protocol: &TlsCommitProtocolConfig) -> Option<String> {
    match protocol {
        TlsCommitProtocolConfig::Mpc(mpc_tls_config) => {
            if mpc_tls_config.max_sent_data() > MAX_SENT_DATA {
                return Some(format!(
                    "max_sent_data too large: {} > {}",
                    mpc_tls_config.max_sent_data(),
                    MAX_SENT_DATA
                ));
            }

            if mpc_tls_config.max_recv_data() > MAX_RECV_DATA {
                return Some(format!(
                    "max_recv_data too large: {} > {}",
                    mpc_tls_config.max_recv_data(),
                    MAX_RECV_DATA
                ));
            }

            None
        }
        _ => Some("expected MPC-TLS protocol".to_string()),
    }
}

fn proving_request_rejection_reason(
    server_identity_revealed: bool,
    reveal_payload_present: bool,
) -> Option<String> {
    if !server_identity_revealed {
        return Some("missing required server identity reveal".to_string());
    }

    if !reveal_payload_present {
        return Some("missing required transcript reveal payload".to_string());
    }

    None
}

fn select_unique_bound_field_for_hash(
    bindings: &HashMap<String, zktlsn::BoundCommitment>,
    proof_committed_hash: &[u8],
) -> Result<(String, [u8; 32]), ProtocolError> {
    let mut matched_field: Option<String> = None;
    let mut expected_hash = [0u8; 32];

    for (field, binding) in bindings {
        let commitment_hash_bytes = binding.hash.hash.value.as_bytes();
        if commitment_hash_bytes.len() != proof_committed_hash.len() {
            continue;
        }
        if commitment_hash_bytes != proof_committed_hash {
            continue;
        }

        if let Some(existing_field) = &matched_field {
            return Err(ProtocolError::CommitmentBindingFailed(format!(
                "proof committed hash matched multiple fields: [{existing_field}, {field}]"
            )));
        }

        expected_hash.copy_from_slice(commitment_hash_bytes);
        matched_field = Some(field.clone());
    }

    matched_field.map_or_else(
        || {
            Err(ProtocolError::CommitmentBindingFailed(
                "proof committed hash does not match any bound transcript commitment".to_string(),
            ))
        },
        |field| Ok((field, expected_hash)),
    )
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
        "Verifier full request view (legend: 🙈 redacted byte, 🔐 committed byte):\n{}",
        request_view
    );
    info!(
        "Verifier full response view (legend: 🙈 redacted byte, 🔐 committed byte):\n{}",
        response_view
    );

    let parsed_request = parser::redacted::Request::from_str(&notarized_transcript.request)
        .map_err(|error| ProtocolError::RequestParse(format!("{error:?}")))?;
    info!(parsed_request = ?parsed_request, "Parsed notarized request");
    log_redacted_request_details(&parsed_request, &notarized_transcript.request);

    let parsed_response = parser::redacted::Response::from_str(&notarized_transcript.response)
        .map_err(|error| ProtocolError::ResponseParse(format!("{error:?}")))?;
    info!(parsed_response = ?parsed_response, "Parsed notarized response");
    log_redacted_response_details(&parsed_response, &notarized_transcript.response);

    for (index, commitment) in notarized_transcript
        .transcript_commitments
        .iter()
        .enumerate()
    {
        match commitment {
            TranscriptCommitment::Hash(hash) => {
                info!(
                    commitment_index = index,
                    commitment_kind = "hash",
                    commitment_direction = ?hash.direction,
                    commitment_alg = ?hash.hash.alg,
                    commitment_hash = ?hash.hash.value,
                    range_start = hash.idx.min().unwrap_or(0),
                    range_end = hash.idx.end().unwrap_or(0),
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

    for commitment in transcript_commitments {
        if let TranscriptCommitment::Hash(hash) = commitment {
            if hash.direction != direction {
                continue;
            }

            let start = hash.idx.min().unwrap_or(0).min(transcript_len);
            let end = hash.idx.end().unwrap_or(0).min(transcript_len);
            if end <= start {
                continue;
            }

            for byte in &mut mask[start..end] {
                *byte = true;
            }
        }
    }

    mask
}

fn render_verifier_view(transcript: &str, commit_mask: &[bool]) -> String {
    let bytes = transcript.as_bytes();
    let max_len = bytes.len().min(commit_mask.len());
    let mut out = String::new();

    for idx in 0..max_len {
        if commit_mask[idx] {
            out.push('🔐');
            continue;
        }

        let byte = bytes[idx];
        if byte == 0 {
            out.push('🙈');
            continue;
        }

        match byte {
            b'\r' | b'\n' => {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            b'\t' => out.push('\t'),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02X}")),
        }
    }

    if commit_mask.len() > bytes.len() {
        let hidden_tail = commit_mask.len() - bytes.len();
        out.push_str(&"🔐".repeat(hidden_tail));
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
                    out.push_str(&format!("\\u{{{:04X}}}", c as u32));
                } else {
                    out.push_str(&format!("\\u{{{:04X}}}x{count}", c as u32));
                }
            }
            c => out.push(c),
        }
    }

    out
}

fn preview_text_range(source: &str, range: &Range<usize>) -> String {
    source
        .get(range.clone())
        .map_or_else(|| "<out-of-bounds>".to_string(), sanitize_log_text)
}

fn log_redacted_request_details(parsed_request: &parser::redacted::Request, request: &str) {
    for (header_key, headers) in &parsed_request.headers {
        for (idx, header) in headers.iter().enumerate() {
            let value_preview = header.value.as_ref().map_or_else(
                || "<redacted>".to_string(),
                |range| preview_text_range(request, range),
            );
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
                name_preview = %preview_text_range(request, &header.name),
                value_preview = %value_preview,
                "Parsed transcript request field"
            );
        }
    }

    for (keypath, body_field) in &parsed_request.body {
        match body_field {
            parser::redacted::Body::KeyValue { key, value } => {
                let value_preview = value.as_ref().map_or_else(
                    || "<redacted>".to_string(),
                    |range| preview_text_range(request, range),
                );
                info!(
                    direction = "request",
                    item = "body-key-value",
                    keypath = %keypath,
                    key_range_start = key.start,
                    key_range_end = key.end,
                    value_revealed = value.is_some(),
                    value_range_start = value.as_ref().map_or(0, |range| range.start),
                    value_range_end = value.as_ref().map_or(0, |range| range.end),
                    key_preview = %preview_text_range(request, key),
                    value_preview = %value_preview,
                    "Parsed transcript request field"
                );
            }
            parser::redacted::Body::Value(range) => {
                info!(
                    direction = "request",
                    item = "body-value",
                    keypath = %keypath,
                    value_range_start = range.start,
                    value_range_end = range.end,
                    value_preview = %preview_text_range(request, range),
                    "Parsed transcript request field"
                );
            }
        }
    }
}

fn log_redacted_response_details(parsed_response: &parser::redacted::Response, response: &str) {
    for (header_key, headers) in &parsed_response.headers {
        for (idx, header) in headers.iter().enumerate() {
            let value_preview = header.value.as_ref().map_or_else(
                || "<redacted>".to_string(),
                |range| preview_text_range(response, range),
            );
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
                name_preview = %preview_text_range(response, &header.name),
                value_preview = %value_preview,
                "Parsed transcript response field"
            );
        }
    }

    for (keypath, body_field) in &parsed_response.body {
        match body_field {
            parser::redacted::Body::KeyValue { key, value } => {
                let value_preview = value.as_ref().map_or_else(
                    || "<redacted>".to_string(),
                    |range| preview_text_range(response, range),
                );
                info!(
                    direction = "response",
                    item = "body-key-value",
                    keypath = %keypath,
                    key_range_start = key.start,
                    key_range_end = key.end,
                    value_revealed = value.is_some(),
                    value_range_start = value.as_ref().map_or(0, |range| range.start),
                    value_range_end = value.as_ref().map_or(0, |range| range.end),
                    key_preview = %preview_text_range(response, key),
                    value_preview = %value_preview,
                    "Parsed transcript response field"
                );
            }
            parser::redacted::Body::Value(range) => {
                info!(
                    direction = "response",
                    item = "body-value",
                    keypath = %keypath,
                    value_range_start = range.start,
                    value_range_end = range.end,
                    value_preview = %preview_text_range(response, range),
                    "Parsed transcript response field"
                );
            }
        }
    }
}

fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    bytes
        .iter()
        .take(max_len)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        ops::Range,
        path::PathBuf,
        str::FromStr,
        sync::{Mutex, OnceLock},
    };

    use futures::io::Cursor;
    use k256::{
        EncodedPoint,
        ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    };
    use parser::JsonFieldRangeExt;
    use rangeset::set::RangeSet;
    use serde::Deserialize;
    use tlsn::hash::{Hash, TypedHash};
    use tlsnotary::{Direction, HashAlgId, PlaintextHash, TranscriptCommitment};
    use zktlsn::{
        DEFAULT_VERIFIER_TICKET_PRIVATE_KEY, NoirProverInputs, Proof, TicketSigner,
        ticket_message_hash,
    };

    use crate::errors::ProtocolError;

    use super::{NotarizedTranscript, ProofMessage, VerificationOutcome, verify_proof_message};

    static PROOF_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE_PROOF: OnceLock<Proof> = OnceLock::new();

    #[derive(Debug, Clone, Deserialize)]
    struct AttestationFixture {
        attestation: String,
        attestation_blinder: Vec<u8>,
    }

    #[test]
    fn verify_proof_message_issues_signed_ticket_for_valid_fixture_proof() {
        let proof = fixture_proof().clone();
        let committed_hash =
            zktlsn::extract_committed_hash_from_proof(&proof).expect("extract committed hash");
        let notarized_transcript =
            notarized_transcript_with_fields(&[(".attestation", committed_hash)], &[]);

        let (verified_fields, signed_ticket) =
            verify_proof_message(&notarized_transcript, ProofMessage::new(proof.clone()))
                .expect("verify proof message");

        assert_eq!(verified_fields, vec![".attestation".to_string()]);
        let transfer =
            zktlsn::extract_transfer_fields_from_proof(&proof).expect("extract transfer fields");
        assert_eq!(signed_ticket.tx_id, transfer.tx_id);
        assert_eq!(signed_ticket.to_user_id, transfer.to_user_id);
        assert_eq!(signed_ticket.amount, transfer.amount);

        let signer =
            TicketSigner::from_hex(DEFAULT_VERIFIER_TICKET_PRIVATE_KEY).expect("load signer");
        let signature = Signature::from_slice(&signed_ticket.signature).expect("parse signature");
        let (pubkey_x, pubkey_y) = signer.public_key_coordinates().expect("load public key");
        let encoded =
            EncodedPoint::from_affine_coordinates(&pubkey_x.into(), &pubkey_y.into(), false);
        let verifying_key = VerifyingKey::from_encoded_point(&encoded).expect("decode public key");
        verifying_key
            .verify_prehash(
                &ticket_message_hash(
                    signed_ticket.tx_id,
                    signed_ticket.to_user_id,
                    signed_ticket.amount,
                ),
                &signature,
            )
            .expect("verify issued ticket signature");
    }

    #[test]
    fn verify_proof_message_rejects_tampered_proof_before_ticket_issue() {
        let mut proof = fixture_proof().clone();
        let committed_hash =
            zktlsn::extract_committed_hash_from_proof(&proof).expect("extract committed hash");
        let notarized_transcript =
            notarized_transcript_with_fields(&[(".attestation", committed_hash)], &[]);
        let original_last = *proof.proof.last().expect("fixture proof bytes");
        *proof.proof.last_mut().expect("fixture proof bytes") = original_last ^ 0x01;

        let error = verify_proof_message(&notarized_transcript, ProofMessage::new(proof))
            .expect_err("tampered proof should fail");
        assert!(matches!(error, ProtocolError::ProofVerificationFailed(_)));
    }

    #[test]
    fn verify_proof_message_rejects_mismatched_committed_hash() {
        let proof = fixture_proof().clone();
        let notarized_transcript =
            notarized_transcript_with_fields(&[(".attestation", [0u8; 32])], &[]);

        let error = verify_proof_message(&notarized_transcript, ProofMessage::new(proof))
            .expect_err("mismatched committed hash should fail");
        assert!(matches!(error, ProtocolError::CommitmentBindingFailed(_)));
        assert!(
            error
                .to_string()
                .contains("does not match any bound transcript commitment")
        );
    }

    #[test]
    fn verify_proof_message_rejects_when_multiple_fields_match_same_hash() {
        let proof = fixture_proof().clone();
        let committed_hash =
            zktlsn::extract_committed_hash_from_proof(&proof).expect("extract committed hash");
        let notarized_transcript = notarized_transcript_with_fields(
            &[
                (".attestation", committed_hash),
                (".mirror", committed_hash),
            ],
            &[(".mirror", fixture_attestation().attestation)],
        );

        let error = verify_proof_message(&notarized_transcript, ProofMessage::new(proof))
            .expect_err("ambiguous committed hash should fail");
        assert!(matches!(error, ProtocolError::CommitmentBindingFailed(_)));
        assert!(error.to_string().contains("matched multiple fields"));
    }

    #[test]
    fn verify_proof_message_rejects_when_no_bound_field_matches() {
        let proof = fixture_proof().clone();
        let notarized_transcript =
            notarized_transcript_with_fields(&[(".attestation", [7u8; 32])], &[]);

        let error = verify_proof_message(&notarized_transcript, ProofMessage::new(proof))
            .expect_err("unmatched field should fail");
        assert!(matches!(error, ProtocolError::CommitmentBindingFailed(_)));
        assert!(
            error
                .to_string()
                .contains("does not match any bound transcript commitment")
        );
    }

    #[test]
    fn verification_failure_outcomes_do_not_include_signed_ticket() {
        let failure = VerificationOutcome::failure("server.test".to_string(), "failed".to_string());
        assert!(failure.signed_ticket.is_none());
        assert!(!failure.success);
    }

    #[test]
    fn proof_message_frame_roundtrip_preserves_payload() {
        smol::block_on(async {
            let message = ProofMessage::new(fixture_proof().clone());
            let mut cursor = Cursor::new(Vec::new());
            message.write_to(&mut cursor).await.expect("write frame");
            cursor.set_position(0);

            let decoded = ProofMessage::read_from(&mut cursor)
                .await
                .expect("read frame");
            assert_eq!(decoded.proof.proof, message.proof.proof);
            assert_eq!(decoded.proof.public_inputs, message.proof.public_inputs);
            assert_eq!(
                decoded.proof.verification_key,
                message.proof.verification_key
            );
        });
    }

    #[test]
    fn verification_outcome_frame_roundtrip_preserves_payload() {
        smol::block_on(async {
            let outcome = VerificationOutcome::success(
                "server.test".to_string(),
                vec![".attestation".to_string()],
                "ok".to_string(),
                TicketSigner::from_hex(DEFAULT_VERIFIER_TICKET_PRIVATE_KEY)
                    .expect("load signer")
                    .sign_ticket(1, 3, 25)
                    .expect("sign ticket"),
            );
            let mut cursor = Cursor::new(Vec::new());
            outcome.write_to(&mut cursor).await.expect("write frame");
            cursor.set_position(0);

            let decoded = VerificationOutcome::read_from(&mut cursor)
                .await
                .expect("read frame");
            assert_eq!(decoded.success, outcome.success);
            assert_eq!(decoded.server_name, outcome.server_name);
            assert_eq!(decoded.verified_fields, outcome.verified_fields);
            assert_eq!(decoded.message, outcome.message);
            assert_eq!(decoded.signed_ticket, outcome.signed_ticket);
        });
    }

    fn fixture_proof() -> &'static Proof {
        FIXTURE_PROOF.get_or_init(|| {
            let _guard = PROOF_LOCK.lock().expect("lock proof generation");
            let fixture = fixture_attestation();
            let attestation_blinder: [u8; 16] = fixture
                .attestation_blinder
                .clone()
                .try_into()
                .expect("fixture blinder length");
            let inputs =
                NoirProverInputs::from_attestation(fixture.attestation, attestation_blinder)
                    .expect("build Noir inputs");

            zktlsn::generate_settlement_bundle_from_inputs(inputs)
                .expect("generate attestation proof")
                .native_proof
        })
    }

    fn fixture_attestation() -> AttestationFixture {
        let path = fixture_path("fixture.json");
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", path.display());
        });
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!("failed to decode {}: {error}", path.display());
        })
    }

    fn notarized_transcript_with_fields(
        committed_fields: &[(&str, [u8; 32])],
        extra_string_fields: &[(&str, String)],
    ) -> NotarizedTranscript {
        let fixture = fixture_attestation();
        let full_response = response_with_fields(&fixture.attestation, extra_string_fields);
        let parsed = parser::standard::Response::from_str(&full_response).expect("parse response");
        let mut keep_ranges = vec![
            parsed.protocol_version_with_space(),
            parsed.status_code_with_space(),
            parsed.status_with_newline(),
        ];
        for (keypath, _) in committed_fields {
            if let parser::standard::Body::KeyValue { key, .. } =
                parsed.body.get(*keypath).expect("field should exist")
            {
                keep_ranges.push(key.with_quotes_and_colon());
            }
        }
        let response = redact_string(&full_response, &keep_ranges);
        let transcript_commitments = committed_fields
            .iter()
            .map(|(keypath, hash)| {
                TranscriptCommitment::Hash(PlaintextHash {
                    direction: Direction::Received,
                    idx: RangeSet::from(body_value_range(&parsed, keypath)),
                    hash: TypedHash {
                        alg: HashAlgId::BLAKE3,
                        value: Hash::try_from(hash.to_vec()).expect("hash length"),
                    },
                })
            })
            .collect::<Vec<_>>();

        NotarizedTranscript {
            server_name: "server.test".to_string(),
            request: "POST /transfers HTTP/1.1\nHost: server.test\n\n".to_string(),
            response,
            transcript_commitments,
        }
    }

    fn response_with_fields(attestation: &str, extra_string_fields: &[(&str, String)]) -> String {
        let mut body = format!(
            "{{\"status\":\"success\",\"txId\":1,\"toUserId\":3,\"amount\":25,\"attestation\":\"{attestation}\""
        );
        for (keypath, value) in extra_string_fields {
            let key = keypath.trim_start_matches('.');
            body.push_str(&format!(",\"{key}\":\"{value}\""));
        }
        body.push('}');

        format!(
            "HTTP/1.1 200 OK\nContent-Type: application/json\nTransfer-Encoding: chunked\n\n{:x}\n{}\n0\n",
            body.len(),
            body,
        )
    }

    fn body_value_range(parsed: &parser::standard::Response, keypath: &str) -> Range<usize> {
        match parsed.body.get(keypath).expect("field should exist") {
            parser::standard::Body::KeyValue { value, .. } => value.clone(),
            parser::standard::Body::Value(range) => range.clone(),
        }
    }

    fn redact_string(input: &str, keep_ranges: &[Range<usize>]) -> String {
        let mut bytes = input.as_bytes().to_vec();
        let mut keep_mask = vec![false; bytes.len()];
        for range in keep_ranges {
            for index in range.clone() {
                keep_mask[index] = true;
            }
        }

        for (index, byte) in bytes.iter_mut().enumerate() {
            if !keep_mask[index] {
                *byte = 0;
            }
        }
        String::from_utf8(bytes).expect("valid UTF-8")
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("evm/testdata")
            .join(name)
    }
}
