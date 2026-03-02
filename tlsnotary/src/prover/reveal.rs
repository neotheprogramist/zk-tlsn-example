use std::ops::Range;

use parser::{
    HttpMessage, JsonFieldRangeExt,
    standard::{Body, Header, Request, Response},
};
use tlsn::{config::prove::ProveConfigBuilder, transcript::TranscriptCommitConfigBuilder};
use tracing::info;

use crate::error::Error;

const MAX_LOG_SNIPPET_BYTES: usize = 96;

#[derive(Debug, Clone, Copy)]
enum TranscriptDirection {
    Sent,
    Received,
}

impl TranscriptDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Sent => "request",
            Self::Received => "response",
        }
    }

    fn apply_reveal(
        self,
        builder: &mut ProveConfigBuilder<'_>,
        range: &Range<usize>,
    ) -> Result<(), Error> {
        match self {
            Self::Sent => {
                builder.reveal_sent(range)?;
            }
            Self::Received => {
                builder.reveal_recv(range)?;
            }
        }
        Ok(())
    }

    fn apply_commit(
        self,
        builder: &mut TranscriptCommitConfigBuilder,
        range: &Range<usize>,
    ) -> Result<(), Error> {
        match self {
            Self::Sent => {
                builder.commit_sent(range)?;
            }
            Self::Received => {
                builder.commit_recv(range)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum DisclosureAction {
    Reveal,
    Commit,
}

impl DisclosureAction {
    fn label(self) -> &'static str {
        match self {
            Self::Reveal => "reveal",
            Self::Commit => "commit",
        }
    }
}

fn preview_range(source: &[u8], range: &Range<usize>) -> String {
    source.get(range.clone()).map_or_else(
        || "<out-of-bounds>".to_string(),
        |slice| {
            let truncated = if slice.len() > MAX_LOG_SNIPPET_BYTES {
                &slice[..MAX_LOG_SNIPPET_BYTES]
            } else {
                slice
            };
            sanitize_log_text(String::from_utf8_lossy(truncated).as_ref())
        },
    )
}

fn sanitize_log_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:04X}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn log_disclosure(
    direction: TranscriptDirection,
    action: DisclosureAction,
    target: &str,
    label: &str,
    range: &Range<usize>,
    source: &[u8],
) {
    info!(
        direction = direction.label(),
        action = action.label(),
        target = %target,
        label = %label,
        range_start = range.start,
        range_end = range.end,
        preview = %preview_range(source, range),
        "Applied transcript disclosure rule"
    );
}

fn log_unmatched_disclosure(
    direction: TranscriptDirection,
    action: &str,
    target: &str,
    label: &str,
) {
    info!(
        direction = direction.label(),
        action = %action,
        target = %target,
        label = %label,
        "Configured transcript disclosure rule did not match content"
    );
}

struct DisclosureBuilders<'builder, 'transcript> {
    prove_config: &'builder mut ProveConfigBuilder<'transcript>,
    transcript_commit_config: &'builder mut TranscriptCommitConfigBuilder<'transcript>,
}

fn apply_disclosure(
    direction: TranscriptDirection,
    action: DisclosureAction,
    target: &str,
    label: &str,
    range: &Range<usize>,
    source: &[u8],
    builders: &mut DisclosureBuilders<'_, '_>,
) -> Result<(), Error> {
    match action {
        DisclosureAction::Reveal => direction.apply_reveal(builders.prove_config, range)?,
        DisclosureAction::Commit => {
            direction.apply_commit(builders.transcript_commit_config, range)?
        }
    }
    log_disclosure(direction, action, target, label, range, source);
    Ok(())
}

fn calculate_padded_range(value: &Range<usize>, commitment_length: usize) -> Range<usize> {
    let value_len = value.end - value.start;
    if value_len > commitment_length {
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

    fn selection_range(&self, body_field: &Body) -> Range<usize> {
        match (self, body_field) {
            (Self::Quoted(_), Body::KeyValue { key, value }) => key.full_pair_quoted(value),
            (Self::Unquoted(_), Body::KeyValue { key, value }) => key.full_pair_unquoted(value),
            (Self::UnquotedPadded(_, padding_len), Body::KeyValue { key: _, value }) => {
                Self::get_padded_range(value, *padding_len)
            }
            (_, Body::Value(range)) => range.clone(),
        }
    }

    fn get_padded_range(value: &Range<usize>, commitment_length: usize) -> Range<usize> {
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

    fn value_range(&self, value: &Range<usize>) -> Range<usize> {
        self.commitment_length
            .map_or_else(|| value.clone(), |len| calculate_padded_range(value, len))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevealConfig {
    pub reveal_headers: Vec<String>,
    pub commit_headers: Vec<String>,
    pub reveal_body_fields: Vec<BodyFieldConfig>,
    pub commit_body_fields: Vec<BodyFieldConfig>,
    pub reveal_keys_commit_values: Vec<KeyValueCommitConfig>,
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
            reveal_body_fields: vec![],
            commit_body_fields: vec![],
            reveal_keys_commit_values: vec![],
        }
    }
}

fn apply_header_rules<M>(
    direction: TranscriptDirection,
    action: DisclosureAction,
    message: &M,
    source: &[u8],
    header_names: &[String],
    builders: &mut DisclosureBuilders<'_, '_>,
) -> Result<(), Error>
where
    M: HttpMessage<Header = Header, Body = Body>,
{
    for header_name in header_names {
        let key = header_name.to_lowercase();
        match message.headers().get(&key) {
            Some(headers) => {
                for (idx, header) in headers.iter().enumerate() {
                    let range = header.name.header_full_range(&header.value);
                    let label = format!("{header_name}[{idx}]");
                    apply_disclosure(
                        direction, action, "header", &label, &range, source, builders,
                    )?;
                }
            }
            None => log_unmatched_disclosure(direction, action.label(), "header", header_name),
        }
    }

    Ok(())
}

fn apply_body_field_rules<M>(
    direction: TranscriptDirection,
    action: DisclosureAction,
    message: &M,
    source: &[u8],
    body_fields: &[BodyFieldConfig],
    builders: &mut DisclosureBuilders<'_, '_>,
) -> Result<(), Error>
where
    M: HttpMessage<Header = Header, Body = Body>,
{
    for body_field in body_fields {
        let keypath = body_field.keypath();
        match message.body().get(keypath) {
            Some(parsed_body_field) => {
                let range = body_field.selection_range(parsed_body_field);
                apply_disclosure(direction, action, "body", keypath, &range, source, builders)?;
            }
            None => log_unmatched_disclosure(direction, action.label(), "body", keypath),
        }
    }

    Ok(())
}

fn apply_reveal_key_commit_value_rules<M>(
    direction: TranscriptDirection,
    message: &M,
    source: &[u8],
    key_value_rules: &[KeyValueCommitConfig],
    builders: &mut DisclosureBuilders<'_, '_>,
) -> Result<(), Error>
where
    M: HttpMessage<Header = Header, Body = Body>,
{
    for key_value_rule in key_value_rules {
        match message.body().get(&key_value_rule.keypath) {
            Some(Body::KeyValue { key, value }) => {
                let key_range = key.with_quotes_and_colon();
                apply_disclosure(
                    direction,
                    DisclosureAction::Reveal,
                    "body-key",
                    &key_value_rule.keypath,
                    &key_range,
                    source,
                    builders,
                )?;

                let value_range = key_value_rule.value_range(value);
                apply_disclosure(
                    direction,
                    DisclosureAction::Commit,
                    "body-value",
                    &key_value_rule.keypath,
                    &value_range,
                    source,
                    builders,
                )?;
            }
            Some(Body::Value(_)) => {
                return Err(Error::InvalidInput(format!(
                    "Expected key-value pair for keypath {}, got standalone value",
                    key_value_rule.keypath
                )));
            }
            None => log_unmatched_disclosure(
                direction,
                "reveal+commit",
                "body-key-value",
                &key_value_rule.keypath,
            ),
        }
    }

    Ok(())
}

fn apply_message_reveal_config<M>(
    direction: TranscriptDirection,
    message: &M,
    source: &[u8],
    start_line_label: &str,
    start_line_range: Range<usize>,
    builders: &mut DisclosureBuilders<'_, '_>,
    config: &RevealConfig,
) -> Result<(), Error>
where
    M: HttpMessage<Header = Header, Body = Body>,
{
    apply_disclosure(
        direction,
        DisclosureAction::Reveal,
        "line",
        start_line_label,
        &start_line_range,
        source,
        builders,
    )?;

    apply_header_rules(
        direction,
        DisclosureAction::Reveal,
        message,
        source,
        &config.reveal_headers,
        builders,
    )?;
    apply_header_rules(
        direction,
        DisclosureAction::Commit,
        message,
        source,
        &config.commit_headers,
        builders,
    )?;

    apply_body_field_rules(
        direction,
        DisclosureAction::Reveal,
        message,
        source,
        &config.reveal_body_fields,
        builders,
    )?;
    apply_body_field_rules(
        direction,
        DisclosureAction::Commit,
        message,
        source,
        &config.commit_body_fields,
        builders,
    )?;

    apply_reveal_key_commit_value_rules(
        direction,
        message,
        source,
        &config.reveal_keys_commit_values,
        builders,
    )?;

    Ok(())
}

pub fn reveal_request<'transcript>(
    request: &[u8],
    prove_config: &mut ProveConfigBuilder<'transcript>,
    transcript_commit_config: &mut TranscriptCommitConfigBuilder<'transcript>,
    config: &RevealConfig,
) -> Result<(), Error> {
    let mut builders = DisclosureBuilders {
        prove_config,
        transcript_commit_config,
    };

    if config.reveal_headers.is_empty()
        && config.commit_headers.is_empty()
        && config.reveal_body_fields.is_empty()
        && config.commit_body_fields.is_empty()
        && config.reveal_keys_commit_values.is_empty()
    {
        let full_range = 0..request.len();
        apply_disclosure(
            TranscriptDirection::Sent,
            DisclosureAction::Reveal,
            "message",
            "full",
            &full_range,
            request,
            &mut builders,
        )?;
        return Ok(());
    }

    let raw_request_str = String::from_utf8(request.to_vec())?;
    let parsed_request: Request = raw_request_str.parse()?;
    let request_line_range =
        parsed_request.method.start..parsed_request.protocol_version.with_newline().end;
    apply_message_reveal_config(
        TranscriptDirection::Sent,
        &parsed_request,
        request,
        "request-line",
        request_line_range,
        &mut builders,
        config,
    )
}

pub fn reveal_response<'transcript>(
    response: &[u8],
    prove_config: &mut ProveConfigBuilder<'transcript>,
    transcript_commit_config: &mut TranscriptCommitConfigBuilder<'transcript>,
    config: &RevealConfig,
) -> Result<(), Error> {
    let mut builders = DisclosureBuilders {
        prove_config,
        transcript_commit_config,
    };

    let raw_response_str = String::from_utf8(response.to_vec())?;
    let parsed_response: Response = raw_response_str.parse()?;
    let status_line_range =
        parsed_response.protocol_version.start..parsed_response.status.with_newline().end;
    apply_message_reveal_config(
        TranscriptDirection::Received,
        &parsed_response,
        response,
        "status-line",
        status_line_range,
        &mut builders,
        config,
    )
}
