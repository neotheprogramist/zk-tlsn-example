use std::{collections::HashMap, ops::Range, sync::Arc};

use futures::{AsyncRead, AsyncWrite};
use thiserror::Error;
use zktls::{
    Direction, HashAlgId, SmolRuntime, TranscriptCommitment, Verifier, VerifierConfig,
    VerifierConfigBundle, VerifierOutput,
    parser::redacted::{Body, Header},
    policy::{standard_protocol_policy, standard_request_policy},
};

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

#[derive(Debug, Error)]
pub enum TransferVerifyError {
    #[error("expected server name '{expected}', got '{actual}'")]
    ServerName { expected: String, actual: String },

    #[error("expected {expected:?} hash algorithm in {direction:?} direction, got {actual:?}")]
    HashAlgorithm {
        expected: HashAlgId,
        actual: HashAlgId,
        direction: Direction,
    },

    #[error("missing {ctx} header '{key}'")]
    MissingHeader { ctx: &'static str, key: String },

    #[error("{ctx} header '{key}' has no value")]
    HeaderWithoutValue { ctx: &'static str, key: String },

    #[error("missing {ctx} body field '{key}'")]
    MissingBodyField { ctx: &'static str, key: String },

    #[error("missing value for {ctx} field '{key}'")]
    MissingFieldValue { ctx: &'static str, key: String },

    #[error("{ctx} header '{key}': expected '{expected}', got '{actual}'")]
    HeaderMismatch {
        ctx: &'static str,
        key: String,
        expected: String,
        actual: String,
    },

    #[error("{ctx} field '{key}': expected {expected}, got {actual}")]
    FieldMismatch {
        ctx: &'static str,
        key: String,
        expected: String,
        actual: String,
    },

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Tlsn(#[from] zktls::Error),
}

pub async fn verify_transfer<T>(
    verifier_config: VerifierConfig,
    socket: T,
    expected_server_name: &str,
    expected_to_username: &str,
) -> Result<(T, VerifierOutput), TransferVerifyError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (socket, output) = Verifier::new()
        .verify(
            VerifierConfigBundle {
                runtime: Arc::new(SmolRuntime),
                config: verifier_config,
            },
            socket,
            standard_protocol_policy(MAX_SENT_DATA, MAX_RECV_DATA),
            standard_request_policy(),
        )
        .await?;
    validate_transfer_attestation(&output, expected_server_name, expected_to_username)?;
    Ok((socket, output))
}

fn validate_transfer_attestation(
    output: &VerifierOutput,
    server_name: &str,
    to_username: &str,
) -> Result<(), TransferVerifyError> {
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

fn expect_server_name(output: &VerifierOutput, expected: &str) -> Result<(), TransferVerifyError> {
    if output.server_name == expected {
        return Ok(());
    }
    Err(TransferVerifyError::ServerName {
        expected: expected.to_string(),
        actual: output.server_name.clone(),
    })
}

fn expect_hash_algorithm(
    output: &VerifierOutput,
    expected: HashAlgId,
) -> Result<(), TransferVerifyError> {
    for commitment in &output.transcript_commitments {
        if let TranscriptCommitment::Hash(hash) = commitment
            && hash.hash.alg != expected
        {
            return Err(TransferVerifyError::HashAlgorithm {
                expected,
                actual: hash.hash.alg,
                direction: hash.direction,
            });
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
) -> Result<(), TransferVerifyError> {
    let header = headers
        .get(&key.to_lowercase())
        .and_then(|headers| headers.first())
        .ok_or_else(|| TransferVerifyError::MissingHeader {
            ctx,
            key: key.to_string(),
        })?;
    let actual = text_at(data, header.value.as_ref(), || {
        TransferVerifyError::HeaderWithoutValue {
            ctx,
            key: key.to_string(),
        }
    })?;
    if actual == expected {
        return Ok(());
    }
    Err(TransferVerifyError::HeaderMismatch {
        ctx,
        key: key.to_string(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn expect_body_string(
    body: &HashMap<String, Body>,
    data: &[u8],
    ctx: &'static str,
    key: &str,
    expected: &str,
) -> Result<(), TransferVerifyError> {
    let actual = body_text(body, data, ctx, key)?;
    if actual == expected {
        return Ok(());
    }
    Err(field_mismatch(
        ctx,
        key,
        format!("'{expected}'"),
        format!("'{actual}'"),
    ))
}

fn expect_body_bool(
    body: &HashMap<String, Body>,
    data: &[u8],
    ctx: &'static str,
    key: &str,
    expected: bool,
) -> Result<(), TransferVerifyError> {
    let actual = body_text(body, data, ctx, key)?;
    match actual.parse::<bool>() {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => Err(field_mismatch(
            ctx,
            key,
            expected.to_string(),
            actual.to_string(),
        )),
        Err(_) => Err(field_mismatch(
            ctx,
            key,
            expected.to_string(),
            actual.to_string(),
        )),
    }
}

fn body_text<'a>(
    body: &HashMap<String, Body>,
    data: &'a [u8],
    ctx: &'static str,
    key: &str,
) -> Result<&'a str, TransferVerifyError> {
    let field = body
        .get(key)
        .ok_or_else(|| TransferVerifyError::MissingBodyField {
            ctx,
            key: key.to_string(),
        })?;
    let range = match field {
        Body::KeyValue { value, .. } => value.as_ref(),
        Body::Value(range) => Some(range),
    };
    text_at(data, range, || TransferVerifyError::MissingFieldValue {
        ctx,
        key: key.to_string(),
    })
}

fn text_at<'a>(
    data: &'a [u8],
    range: Option<&Range<usize>>,
    missing: impl FnOnce() -> TransferVerifyError,
) -> Result<&'a str, TransferVerifyError> {
    let range = range.ok_or_else(missing)?;
    Ok(std::str::from_utf8(&data[range.clone()])?)
}

fn field_mismatch(
    ctx: &'static str,
    key: &str,
    expected: String,
    actual: String,
) -> TransferVerifyError {
    TransferVerifyError::FieldMismatch {
        ctx,
        key: key.to_string(),
        expected,
        actual,
    }
}
