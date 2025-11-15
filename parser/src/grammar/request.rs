use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use crate::{
    error::ParserError,
    grammar::common::{CommonParser, CommonRule, CommonRuleType},
    types::{RangedText, Request},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BodySearchable, search::HeaderSearchable, types::RangedValue};

    #[test]
    fn test_parse_simple_get_request() {
        let input = "GET /api/users HTTP/1.1\nHost: example.com\n\n";
        let result = RequestParser::parse_request(input);

        assert!(result.is_ok());
        let request = result.unwrap();

        assert_eq!(request.request_line.value, "GET /api/users HTTP/1.1\n");
        assert_eq!(request.request_line.range.start, 0);

        assert_eq!(request.headers.len(), 1);

        let host_header = request
            .headers
            .get("Host")
            .expect("Host header should exist");
        assert_eq!(host_header.range, 24..42);
        assert_eq!(host_header.value, "example.com");

        assert!(request.body.is_none());
    }

    #[test]
    fn test_parse_post_request_with_json_object() {
        let input = r#"POST /api/users HTTP/1.1
Host: example.com
Content-Type: application/json

{"name":"Alice", "age":30}"#;

        let result = RequestParser::parse_request(input);
        assert!(result.is_ok());

        let request = result.unwrap();

        assert_eq!(request.request_line.value, *"POST /api/users HTTP/1.1\n");

        assert_eq!(request.headers.len(), 2);

        let host_header = request
            .headers
            .get("Host")
            .expect("Host header should exist");
        assert_eq!(host_header.range, 25..43);
        assert_eq!(host_header.value, "example.com");

        let content_type_header = request
            .headers
            .get("Content-Type")
            .expect("Content-Type header should exist");
        assert_eq!(content_type_header.range, 43..74);
        assert_eq!(content_type_header.value, "application/json");

        assert!(request.body.is_some());
        match request.body.as_ref().unwrap() {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("name"));
                assert!(value.contains_key("age"));
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_parse_request_with_json_array() {
        let input = r#"POST /api/batch HTTP/1.1
Host: example.com

[1, 2, 3, 4, 5]"#;

        let result = RequestParser::parse_request(input);
        assert!(result.is_ok());

        let request = result.unwrap();
        match request.body.as_ref().unwrap() {
            RangedValue::Array { value, .. } => {
                assert_eq!(value.len(), 5);
            }
            _ => panic!("Expected array content"),
        }
    }

    #[test]
    fn test_parse_request_with_nested_json() {
        let input = r#"POST /api/users HTTP/1.1
Host: example.com

{"user":{"name":"Bob", "details":{"age":25, "city":"NYC"}}}"#;

        let result = RequestParser::parse_request(input);
        assert!(result.is_ok());

        let request = result.unwrap();
        match request.body.as_ref().unwrap() {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("user"));
                match &value["user"] {
                    RangedValue::Object {
                        value: user_obj, ..
                    } => {
                        assert!(user_obj.contains_key("name"));
                        assert!(user_obj.contains_key("details"));
                    }
                    _ => panic!("Expected nested object"),
                }
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_parse_request_with_multiple_headers() {
        let input = r#"GET /api/data HTTP/1.1
Host: api.example.com
User-Agent: TestClient/1.0
Accept: application/json
Authorization: Bearer token123

"#;

        let result = RequestParser::parse_request(input);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert_eq!(request.headers.len(), 4);

        let host_header = request
            .headers
            .get("Host")
            .expect("Host header should exist");
        assert_eq!(host_header.range, 23..45);
        assert_eq!(host_header.value, "api.example.com");

        let user_agent_header = request
            .headers
            .get("User-Agent")
            .expect("User-Agent header should exist");
        assert_eq!(user_agent_header.range, 45..72);
        assert_eq!(user_agent_header.value, "TestClient/1.0");

        let accept_header = request
            .headers
            .get("Accept")
            .expect("Accept header should exist");
        assert_eq!(accept_header.range, 72..97);
        assert_eq!(accept_header.value, "application/json");

        let auth_header = request
            .headers
            .get("Authorization")
            .expect("Authorization header should exist");
        assert_eq!(auth_header.range, 97..128);
        assert_eq!(auth_header.value, "Bearer token123");
    }

    #[test]
    fn test_parse_request_with_special_chars_in_url() {
        let input = "GET /api/search?q=hello%20world&page=1 HTTP/1.1\nHost: example.com\n\n";
        let result = RequestParser::parse_request(input);

        assert!(result.is_ok());
        let request = result.unwrap();
        assert_eq!(
            request.request_line.value,
            "GET /api/search?q=hello%20world&page=1 HTTP/1.1\n"
        );
    }

    #[test]
    fn test_invalid_request_missing_request_line() {
        let input = "Host: example.com\n\n";
        let result = RequestParser::parse_request(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_request_range_tracking() {
        let input = r#"POST /api/users HTTP/1.1
Host: example.com

{"id":123}"#;

        let result = RequestParser::parse_request(input);
        assert!(result.is_ok());

        let request = result.unwrap();

        assert_eq!(request.request_line.range.start, 0);
        assert!(request.request_line.range.end > 0);

        for header in request.headers.values() {
            assert!(header.range.start < header.range.end);
        }

        if let Some(content) = &request.body {
            let range = content.get_range();
            assert!(range.start < range.end);
        }
    }

    #[test]
    fn test_search_request_headers() {
        let input = r#"POST /api/users HTTP/1.1
Host: example.com
Content-Type: application/json

{"name":"Alice"}"#;

        let request = RequestParser::parse_request(input).unwrap();
        let header_ranges = request
            .get_header_ranges(&["Host", "Content-Type"])
            .unwrap();

        assert_eq!(header_ranges.len(), 2);
    }

    #[test]
    fn test_search_request_keypaths() {
        let input = r#"POST /api/users HTTP/1.1
Host: example.com

{"user":{"name":"Alice", "age":30}}"#;

        let request = RequestParser::parse_request(input).unwrap();
        let body_ranges = request.get_body_keypaths_ranges(&["user.name"]).unwrap();

        assert_eq!(body_ranges.len(), 1);
    }

    #[test]
    fn test_different_http_methods() {
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

        for method in methods {
            let input = format!("{} /api/test HTTP/1.1\nHost: example.com\n\n", method);
            let result = RequestParser::parse_request(&input);
            assert!(result.is_ok(), "Failed to parse {} request", method);
            let request = result.unwrap();
            let expected = format!("{} /api/test HTTP/1.1\n", method);
            assert_eq!(request.request_line.value, expected);
        }
    }
}
