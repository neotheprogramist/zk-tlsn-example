use std::ops::Range;

use tlsn::{config::prove::ProveConfigBuilder, transcript::TranscriptCommitConfigBuilder};
use tracing::info;

use crate::{
    Error,
    parser::{
        HttpMessage, JsonFieldRangeExt,
        standard::{Body, Header, Request as ParsedRequest, Response as ParsedResponse},
    },
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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
                calculate_padded_range(value, *padding_len)
            }
            (_, Body::Value(range)) => range.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealConfig {
    pub reveal_headers: Vec<String>,
    pub commit_headers: Vec<String>,
    pub reveal_body_fields: Vec<BodyFieldConfig>,
    pub commit_body_fields: Vec<BodyFieldConfig>,
    pub reveal_keys_commit_values: Vec<KeyValueCommitConfig>,
}

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
            Self::Sent => builder.reveal_sent(range)?,
            Self::Received => builder.reveal_recv(range)?,
        };
        Ok(())
    }

    fn apply_commit(
        self,
        builder: &mut TranscriptCommitConfigBuilder,
        range: &Range<usize>,
    ) -> Result<(), Error> {
        match self {
            Self::Sent => builder.commit_sent(range)?,
            Self::Received => builder.commit_recv(range)?,
        };
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

struct DisclosureBuilders<'b, 't> {
    prove_config: &'b mut ProveConfigBuilder<'t>,
    transcript_commit_config: &'b mut TranscriptCommitConfigBuilder<'t>,
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
    info!(
        direction = direction.label(),
        action = action.label(),
        target = %target,
        label = %label,
        range_start = range.start,
        range_end = range.end,
        preview = %preview_range(source, range),
        "zktls.reveal.range"
    );
    Ok(())
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

fn calculate_padded_range(value: &Range<usize>, commitment_length: usize) -> Range<usize> {
    let value_len = value.end - value.start;
    if value_len > commitment_length {
        return value.clone();
    }
    value.start..(value.start + commitment_length)
}

fn apply_rules<R, T>(
    rules: &[R],
    mut find: impl FnMut(&R) -> Result<T, Error>,
    mut disclose: impl FnMut(&R, T) -> Result<(), Error>,
) -> Result<(), Error> {
    rules.iter().try_for_each(|rule| {
        let target = find(rule)?;
        disclose(rule, target)
    })
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

    for (names, action) in [
        (&config.reveal_headers, DisclosureAction::Reveal),
        (&config.commit_headers, DisclosureAction::Commit),
    ] {
        apply_rules(
            names,
            |name| {
                message.headers().get(&name.to_lowercase()).ok_or_else(|| {
                    Error::RevealRuleNotMatched {
                        direction: direction.label(),
                        target: "header",
                        rule: name.clone(),
                    }
                })
            },
            |name, headers| {
                headers.iter().enumerate().try_for_each(|(idx, header)| {
                    let range = header.name.header_full_range(&header.value);
                    let label = format!("{name}[{idx}]");
                    apply_disclosure(
                        direction, action, "header", &label, &range, source, builders,
                    )
                })
            },
        )?;
    }

    for (fields, action) in [
        (&config.reveal_body_fields, DisclosureAction::Reveal),
        (&config.commit_body_fields, DisclosureAction::Commit),
    ] {
        apply_rules(
            fields,
            |field| {
                message
                    .body()
                    .get(field.keypath())
                    .ok_or_else(|| Error::RevealRuleNotMatched {
                        direction: direction.label(),
                        target: "body",
                        rule: field.keypath().to_string(),
                    })
            },
            |field, body_field| {
                let range = field.selection_range(body_field);
                apply_disclosure(
                    direction,
                    action,
                    "body",
                    field.keypath(),
                    &range,
                    source,
                    builders,
                )
            },
        )?;
    }

    apply_rules(
        &config.reveal_keys_commit_values,
        |rule| {
            message
                .body()
                .get(&rule.keypath)
                .ok_or_else(|| Error::RevealRuleNotMatched {
                    direction: direction.label(),
                    target: "body-key-value",
                    rule: rule.keypath.clone(),
                })
                .and_then(|body_field| match body_field {
                    Body::KeyValue { key, value } => Ok((key, value)),
                    Body::Value(_) => Err(Error::RevealStructureMismatch {
                        rule: rule.keypath.clone(),
                        expected: "key-value",
                        actual: "value",
                    }),
                })
        },
        |rule, (key, value)| {
            let key_range = key.with_quotes_and_colon();
            apply_disclosure(
                direction,
                DisclosureAction::Reveal,
                "body-key",
                &rule.keypath,
                &key_range,
                source,
                builders,
            )?;
            let value_range = rule.value_range(value);
            apply_disclosure(
                direction,
                DisclosureAction::Commit,
                "body-value",
                &rule.keypath,
                &value_range,
                source,
                builders,
            )
        },
    )
}

pub(crate) fn reveal_request<'transcript>(
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
        return apply_disclosure(
            TranscriptDirection::Sent,
            DisclosureAction::Reveal,
            "message",
            "full",
            &full_range,
            request,
            &mut builders,
        );
    }

    let raw_request_str = String::from_utf8(request.to_vec())?;
    let parsed_request: ParsedRequest = raw_request_str.parse()?;
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

pub(crate) fn reveal_response<'transcript>(
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
    let parsed_response: ParsedResponse = raw_response_str.parse()?;
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
