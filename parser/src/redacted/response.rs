use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use super::types::Response;
use crate::{
    common::{CommonParser, CommonRule, CommonRuleType},
    error::ParserError,
    ranged::RangedText,
};

#[derive(Parser)]
#[grammar = "./redacted/response.pest"]
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
        let mut body = HashMap::new();

        for pair in pairs {
            match pair.as_rule() {
                Rule::status_line => {
                    let span = pair.as_span();
                    let range = span.start()..span.end();
                    let value = span.as_str().trim_end().to_string();
                    status_line = Some(RangedText { range, value });
                }
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::partially_redacted_body => {
                    for inner_pair in pair.into_inner() {
                        if inner_pair.as_rule() == Rule::pair {
                            let (key, value) = CommonParser::parse_pair(inner_pair)?;
                            body.insert(key, value);
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
            Rule::object => Ok(CommonRuleType::Object),
            Rule::array => Ok(CommonRuleType::Array),
            Rule::string => Ok(CommonRuleType::String),
            Rule::number => Ok(CommonRuleType::Number),
            Rule::boolean => Ok(CommonRuleType::Boolean),
            Rule::null => Ok(CommonRuleType::Null),
            _ => Err(ParserError::InvalidValue),
        }
    }
}
