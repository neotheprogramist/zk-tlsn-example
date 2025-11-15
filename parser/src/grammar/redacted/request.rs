use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use crate::{
    error::ParserError,
    grammar::common::{CommonParser, CommonRule, CommonRuleType},
    types::{RangedText, Request},
};

#[derive(Parser)]
#[grammar = "./grammar/redacted/request.pest"]
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
        let mut body = None;

        for pair in pairs {
            match pair.as_rule() {
                Rule::request_line => {
                    let range = pair.as_span().start()..pair.as_span().end();
                    request_line = Some(RangedText {
                        range,
                        value: pair.as_str().to_string(),
                    });
                }
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::redacted_header_line => {}
                Rule::redacted_body => {
                    if let Some(json_pair) = pair
                        .into_inner()
                        .find(|p| p.as_rule() == Rule::redacted_json)
                    {
                        body = Some(CommonParser::parse_value(
                            json_pair
                                .into_inner()
                                .next()
                                .ok_or(ParserError::MissingField("request body content"))?,
                        )?);
                    }
                }
                _ => continue,
            }
        }

        Ok(Request::new(
            request_line.ok_or(ParserError::MissingField("request line"))?,
            headers,
            body,
        ))
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
    fn test_parse_redacted_request() {
        let input = "GET /api/balance/alice HTTP/1.1\r\ncontent-type: application/json\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let result = RedactedRequestParser::parse_redacted_request(input);

        assert!(result.is_ok());
        let request = result.unwrap();

        assert_eq!(
            request.request_line.value,
            "GET /api/balance/alice HTTP/1.1\r\n"
        );
        assert_eq!(request.headers.len(), 1);
        assert!(request.headers.contains_key("content-type"));
    }
}
