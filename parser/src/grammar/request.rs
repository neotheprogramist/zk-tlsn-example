use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use crate::{
    error::ParserError,
    grammar::common::{CommonParser, CommonRule, CommonRuleType},
    types::{RangedHeader, Request},
};

#[derive(Parser)]
#[grammar = "./grammar/request.pest"]
pub struct RequestParser;

impl RequestParser {
    pub fn parse_request(input: &str) -> Result<Request, ParserError> {
        let pairs = Self::parse(Rule::request, input)
            .map_err(|e| ParserError::RequestParseFailed(format!("Pest parsing failed: {}", e)))?;

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
                    request_line = Some(RangedHeader {
                        range,
                        value: pair.as_str().to_string(),
                    });
                }
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::body => {
                    body = Some(CommonParser::parse_value(
                        pair.into_inner()
                            .next()
                            .ok_or(ParserError::MissingField("request body"))?,
                    )?);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_get_request() {
        let input = "GET /api/users HTTP/1.1\nHost: example.com\n\n";
        let result = RequestParser::parse_request(input);
        assert!(result.is_ok());
        let request = result.unwrap();
        assert!(request.request_line.value.contains("GET"));
        assert!(request.headers.contains_key("Host"));
    }

    #[test]
    fn test_parse_post_request_with_json() {
        let input = r#"POST /api/users HTTP/1.1
Host: example.com
Content-Type: application/json

{"name":"Alice","age":30}"#;
        let result = RequestParser::parse_request(input);
        if let Err(e) = &result {
            eprintln!("Parse error: {:?}", e);
        }
        assert!(result.is_ok());
        let request = result.unwrap();
        assert!(request.body.is_some());
    }
}
