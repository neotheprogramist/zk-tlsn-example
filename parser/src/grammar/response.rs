use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use crate::{
    error::ParserError,
    grammar::common::{CommonParser, CommonRule, CommonRuleType},
    types::{RangedValue, Response},
};

#[derive(Parser)]
#[grammar = "./grammar/response.pest"]
pub struct ResponseParser;

impl ResponseParser {
    pub fn parse_response(input: &str) -> Result<Response, ParserError> {
        let pairs = Self::parse(Rule::response, input)
            .map_err(|e| ParserError::ResponseParseFailed(format!("Pest parsing failed: {}", e)))?;

        Self::build_response(pairs)
    }

    fn build_response(pairs: Pairs<Rule>) -> Result<Response, ParserError> {
        let mut headers = HashMap::new();
        let mut body = RangedValue::default();

        for pair in pairs {
            match pair.as_rule() {
                Rule::header => {
                    let (key, value) = CommonParser::parse_header(pair)?;
                    headers.insert(key, value);
                }
                Rule::body => {
                    body = CommonParser::parse_value(
                        pair.into_inner()
                            .next()
                            .ok_or(ParserError::MissingField("response body"))?,
                    )?;
                }
                _ => continue,
            }
        }

        Ok(Response::new(headers, body))
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
    fn test_parse_simple_response() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

15
{"status":"success"}
0
"#;
        let result = ResponseParser::parse_response(input);
        if let Err(e) = &result {
            eprintln!("Parse error: {:?}", e);
        }
        assert!(result.is_ok());
    }
}
