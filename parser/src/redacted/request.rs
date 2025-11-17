use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use super::types::Request;
use crate::{
    common::{CommonParser, CommonRule, CommonRuleType},
    error::ParserError,
    ranged::RangedText,
};

#[derive(Parser)]
#[grammar = "./redacted/request.pest"]
pub struct RedactedRequestParser;

impl RedactedRequestParser {
    pub fn parse_redacted_request(input: &str) -> Result<Request, ParserError> {
        let pairs = Self::parse(Rule::redacted_request, input).map_err(|e| {
            ParserError::RequestParseFailed(format!("Redacted request parsing failed: {}", e))
        })?;

        Self::build_request(pairs)
    }

    fn build_request(pairs: Pairs<Rule>) -> Result<Request, ParserError> {
        let mut request_line = None;
        let mut headers = HashMap::new();
        let mut body = HashMap::new();

        for pair in pairs {
            match pair.as_rule() {
                Rule::request_line => {
                    let span = pair.as_span();
                    let range = span.start()..span.end();
                    let value = span.as_str().trim_end().to_string();
                    request_line = Some(RangedText { range, value });
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

        let request_line = request_line.ok_or(ParserError::MissingField("request line"))?;

        Ok(Request::new(request_line, headers, body))
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
