use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use crate::{
    error::ParserError,
    grammar::common::{CommonParser, CommonRule, CommonRuleType},
    types::{RangedValue, Response},
};

#[derive(Parser)]
#[grammar = "./grammar/redacted/response.pest"]
pub struct RedactedResponseParser;

impl RedactedResponseParser {
    pub fn parse_redacted_response(input: &str) -> Result<Response, ParserError> {
        let pairs = Self::parse(Rule::redacted_response, input).map_err(|e| {
            ParserError::ResponseParseFailed(format!("Redacted response parsing failed: {}", e))
        })?;

        Self::build_response(pairs)
    }

    fn build_response(pairs: Pairs<Rule>) -> Result<Response, ParserError> {
        let mut status_line = None;
        let mut headers = HashMap::new();
        let mut body = RangedValue::default();

        for pair in pairs {
            match pair.as_rule() {
                Rule::status_line => {
                    let span = pair.as_span();
                    let range = span.start()..span.end();
                    let value = span.as_str().trim_end().to_string();
                    status_line = Some(crate::types::RangedText { range, value });
                }
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::redacted_header_line => {}
                Rule::redacted_body => {
                    for inner_pair in pair.into_inner() {
                        match inner_pair.as_rule() {
                            Rule::redacted_chunked_body | Rule::redacted_content_length_body => {
                                for content_pair in inner_pair.into_inner() {
                                    if content_pair.as_rule() == Rule::mixed_content
                                        && let Some(json_pair) = content_pair
                                            .into_inner()
                                            .find(|p| p.as_rule() == Rule::redacted_json)
                                    {
                                        body = CommonParser::parse_value(
                                            json_pair.into_inner().next().ok_or(
                                                ParserError::MissingField("response body content"),
                                            )?,
                                        )?;
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => continue,
            }
        }

        let status_line = status_line.ok_or(ParserError::MissingField("response status line"))?;

        Ok(Response::new(status_line, headers, body))
    }
}

impl CommonRule for Rule {
    fn rule_type(&self) -> Result<CommonRuleType, ParserError> {
        match self {
            Rule::redacted_object => Ok(CommonRuleType::Object),
            Rule::redacted_array => Ok(CommonRuleType::Array),
            Rule::string => Ok(CommonRuleType::String),
            Rule::number => Ok(CommonRuleType::Number),
            Rule::boolean => Ok(CommonRuleType::Boolean),
            Rule::null => Ok(CommonRuleType::Null),
            Rule::redacted_string => Ok(CommonRuleType::String),
            Rule::redacted_literal => Ok(CommonRuleType::String),
            _ => Err(ParserError::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_redacted_response() {
        let input = "HTTP/1.1 200 OK\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\"username\":\"alice\"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let result = RedactedResponseParser::parse_redacted_response(input);

        if result.is_err() {
            eprintln!("Parse error: {:?}", result.as_ref().unwrap_err());
        }

        assert!(result.is_ok());
        let response = result.unwrap();

        assert_eq!(response.status_line.value, "HTTP/1.1 200 OK");
        assert_eq!(response.headers.len(), 0);
    }
}
