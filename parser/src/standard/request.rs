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
#[grammar = "./standard/request.pest"]
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
                    request_line = Some(RangedText {
                        range,
                        value: pair.as_str().to_string(),
                    });
                }
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::body => {
                    let json_pair = pair
                        .into_inner()
                        .find(|p| p.as_rule() == Rule::json)
                        .ok_or(ParserError::MissingField("request body"))?;

                    body = Some(CommonParser::parse_value(
                        json_pair
                            .into_inner()
                            .next()
                            .ok_or(ParserError::MissingField("request body content"))?,
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
