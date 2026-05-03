use std::{collections::HashMap, ops::Range};

use futures::{AsyncRead, AsyncWrite, channel::oneshot};
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    hash::HashAlgId,
    transcript::PartialTranscript,
};

use crate::{
    error::{Error, TranscriptError},
    flow::{MAX_RECV_DATA, MAX_SENT_DATA},
    parser::redacted::{Body, Header, Request, Response},
    transport::{Runtime, SmolRuntime},
};

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub server_name: String,
    pub parsed_request: Request,
    pub parsed_response: Response,
}

pub struct Verifier {
    verifier_config: VerifierConfig,
}

impl Verifier {
    #[must_use]
    pub fn new(verifier_config: VerifierConfig) -> Self {
        Self { verifier_config }
    }

    pub async fn verify<T>(
        self,
        socket: T,
        protocol_policy: impl FnOnce(&TlsCommitProtocolConfig) -> Result<(), String>,
        request_policy: impl FnOnce(bool, bool) -> Result<(), String>,
    ) -> Result<(T, VerifierOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut session = Session::new(socket);
        let verifier = session.new_verifier(self.verifier_config)?;
        let (driver, handle) = session.split();

        let (socket_tx, socket_rx) = oneshot::channel();
        SmolRuntime.spawn_detached(Box::pin(async move {
            let outcome = driver.await.map_err(Error::from);
            // PROOF: the receiver is awaited below; if it has been dropped,
            // the verifier has already returned an error upstream and the
            // consumer side maps the closed channel to
            // `Error::SessionDriverCancelled`. We log the drop rather than
            // discard it silently so the event is observable in tracing.
            if socket_tx.send(outcome).is_err() {
                tracing::warn!("verifier socket oneshot receiver dropped before driver finished");
            }
        }));

        let verifier = verifier.commit().await?;
        if let Err(reason) = protocol_policy(verifier.request().protocol()) {
            verifier.reject(Some(&reason)).await?;
            return Err(Error::PolicyRejected {
                context: "protocol",
                reason,
            });
        }

        let verifier = verifier.accept().await?.run().await?.verify().await?;
        if let Err(reason) = request_policy(
            verifier.request().server_identity(),
            verifier.request().reveal().is_some(),
        ) {
            let verifier = verifier.reject(Some(&reason)).await?;
            verifier.close().await?;
            return Err(Error::PolicyRejected {
                context: "request",
                reason,
            });
        }

        let (output, verifier) = verifier.accept().await?;
        verifier.close().await?;
        handle.close();

        let socket = socket_rx
            .await
            .map_err(|_| Error::SessionDriverCancelled)
            .and_then(|inner| inner)?;

        let server_name = output
            .server_name
            .ok_or(Error::MissingField("server name"))?;
        let transcript = output.transcript.ok_or(Error::MissingField("transcript"))?;

        let sent_data = String::from_utf8(transcript.sent_unsafe().to_vec())?;
        let received_data = String::from_utf8(transcript.received_unsafe().to_vec())?;
        let parsed_request: Request = sent_data.parse()?;
        let parsed_response: Response = received_data.parse()?;

        Ok((
            socket,
            VerifierOutput {
                transcript,
                transcript_commitments: output.transcript_commitments,
                server_name: server_name.to_string(),
                parsed_request,
                parsed_response,
            },
        ))
    }

    pub async fn verify_transfer<T>(
        self,
        socket: T,
        expected_server_name: &str,
        expected_to_username: &str,
    ) -> Result<(T, VerifierOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (socket, output) = self
            .verify(socket, transfer_protocol_policy, transfer_reveal_policy)
            .await?;
        validate_transfer_attestation(&output, expected_server_name, expected_to_username)?;
        Ok((socket, output))
    }
}

fn transfer_protocol_policy(protocol: &TlsCommitProtocolConfig) -> Result<(), String> {
    let TlsCommitProtocolConfig::Mpc(mpc) = protocol else {
        return Err("expected MPC-TLS protocol".to_string());
    };
    if mpc.max_sent_data() > MAX_SENT_DATA {
        return Err("max_sent_data exceeds limit".to_string());
    }
    if mpc.max_recv_data() > MAX_RECV_DATA {
        return Err("max_recv_data exceeds limit".to_string());
    }
    Ok(())
}

fn transfer_reveal_policy(
    server_identity_revealed: bool,
    reveal_payload_present: bool,
) -> Result<(), String> {
    if !server_identity_revealed {
        return Err("missing required server identity reveal".to_string());
    }
    if !reveal_payload_present {
        return Err("missing required transcript reveal payload".to_string());
    }
    Ok(())
}

fn validate_transfer_attestation(
    output: &VerifierOutput,
    server_name: &str,
    to_username: &str,
) -> Result<(), Error> {
    expect_server_name(output, server_name)?;
    expect_hash_algorithm(output, HashAlgId::BLAKE3)?;
    expect_header(
        &output.parsed_request.headers,
        output.transcript.sent_unsafe(),
        "request",
        "content-type",
        "application/json",
    )?;
    expect_body_string(
        &output.parsed_response.body,
        output.transcript.received_unsafe(),
        "response",
        ".toUsername",
        to_username,
    )?;
    expect_body_bool(
        &output.parsed_response.body,
        output.transcript.received_unsafe(),
        "response",
        ".eligibleForMint",
        true,
    )
}

fn expect_server_name(output: &VerifierOutput, expected: &str) -> Result<(), Error> {
    if output.server_name == expected {
        return Ok(());
    }
    Err(TranscriptError::ServerName {
        expected: expected.to_string(),
        actual: output.server_name.clone(),
    }
    .into())
}

fn expect_hash_algorithm(output: &VerifierOutput, expected: HashAlgId) -> Result<(), Error> {
    for commitment in &output.transcript_commitments {
        if let tlsn::transcript::TranscriptCommitment::Hash(hash) = commitment
            && hash.hash.alg != expected
        {
            return Err(TranscriptError::HashAlgorithm {
                expected,
                actual: hash.hash.alg,
                direction: hash.direction,
            }
            .into());
        }
    }
    Ok(())
}

fn expect_header(
    headers: &HashMap<String, Vec<Header>>,
    data: &[u8],
    ctx: &'static str,
    key: &str,
    expected: &str,
) -> Result<(), Error> {
    let header = headers
        .get(&key.to_lowercase())
        .and_then(|headers| headers.first())
        .ok_or_else(|| TranscriptError::MissingHeader {
            ctx,
            key: key.to_string(),
        })?;
    let actual = text_at(data, header.value.as_ref(), || {
        TranscriptError::HeaderWithoutValue {
            ctx,
            key: key.to_string(),
        }
    })?;
    if actual == expected {
        return Ok(());
    }
    Err(TranscriptError::HeaderMismatch {
        ctx,
        key: key.to_string(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    }
    .into())
}

fn expect_body_string(
    body: &HashMap<String, Body>,
    data: &[u8],
    ctx: &'static str,
    key: &str,
    expected: &str,
) -> Result<(), Error> {
    let actual = body_text(body, data, ctx, key)?;
    if actual == expected {
        return Ok(());
    }
    Err(field_mismatch(ctx, key, format!("'{expected}'"), format!("'{actual}'")).into())
}

fn expect_body_bool(
    body: &HashMap<String, Body>,
    data: &[u8],
    ctx: &'static str,
    key: &str,
    expected: bool,
) -> Result<(), Error> {
    let actual = body_text(body, data, ctx, key)?;
    match actual.parse::<bool>() {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => {
            Err(field_mismatch(ctx, key, expected.to_string(), actual.to_string()).into())
        }
        Err(_) => Err(field_mismatch(ctx, key, expected.to_string(), actual.to_string()).into()),
    }
}

fn body_text<'a>(
    body: &HashMap<String, Body>,
    data: &'a [u8],
    ctx: &'static str,
    key: &str,
) -> Result<&'a str, Error> {
    let field = body
        .get(key)
        .ok_or_else(|| TranscriptError::MissingBodyField {
            ctx,
            key: key.to_string(),
        })?;
    let range = match field {
        Body::KeyValue { value, .. } => value.as_ref(),
        Body::Value(range) => Some(range),
    };
    text_at(data, range, || TranscriptError::MissingFieldValue {
        ctx,
        key: key.to_string(),
    })
}

fn text_at<'a>(
    data: &'a [u8],
    range: Option<&Range<usize>>,
    missing: impl FnOnce() -> TranscriptError,
) -> Result<&'a str, Error> {
    let range = range.ok_or_else(missing)?;
    Ok(std::str::from_utf8(&data[range.clone()])?)
}

fn field_mismatch(
    ctx: &'static str,
    key: &str,
    expected: String,
    actual: String,
) -> TranscriptError {
    TranscriptError::FieldMismatch {
        ctx,
        key: key.to_string(),
        expected,
        actual,
    }
}
