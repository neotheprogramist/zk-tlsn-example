use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use super::types::Response;
use crate::{
    common::{CommonParser, CommonRule, CommonRuleType},
    error::ParserError,
    ranged::RangedValue,
};

#[derive(Parser)]
#[grammar = "./standard/response.pest"]
pub struct ResponseParser;

impl ResponseParser {
    pub fn parse_response(input: &str) -> Result<Response, ParserError> {
        let pairs = Self::parse(Rule::response, input)
            .map_err(|e| ParserError::ResponseParseFailed(format!("Pest parsing failed: {}", e)))?;

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
                    status_line = Some(crate::ranged::RangedText { range, value });
                }
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::chunked_body | Rule::content_length_body => {
                    let body_pair = pair
                        .into_inner()
                        .find(|p| p.as_rule() == Rule::json)
                        .ok_or(ParserError::MissingField("response body"))?;

                    body = CommonParser::parse_value(
                        body_pair
                            .into_inner()
                            .next()
                            .ok_or(ParserError::MissingField("response body content"))?,
                    )?;
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
