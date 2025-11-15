use std::collections::HashMap;

use pest::{Parser, iterators::Pairs};
use pest_derive::Parser;

use crate::{
    error::ParserError,
    grammar::common::{CommonParser, CommonRule, CommonRuleType},
    types::{RangedValue, Response},
};

#[derive(Parser)]
#[grammar = "./grammar/standard/response.pest"]
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
                    status_line = Some(crate::types::RangedText { range, value });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        search::{BodySearchable, HeaderSearchable},
        types::RangedValue,
    };

    #[test]
    fn test_parse_simple_response() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

1a
{"status":"success"}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();

        assert_eq!(response.headers.len(), 1);

        let content_type_header = response
            .headers
            .get("Content-Type")
            .expect("Content-Type header should exist");
        assert_eq!(content_type_header.range, 16..47);
        assert_eq!(content_type_header.value, "application/json");

        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("status"));
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_parse_response_with_multiple_headers() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json
Server: nginx/1.18.0
Date: Mon, 01 Jan 2024 00:00:00 GMT

1a
{"data":"test"}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.headers.len(), 3);

        let content_type_header = response
            .headers
            .get("Content-Type")
            .expect("Content-Type header should exist");
        assert_eq!(content_type_header.range, 16..47);
        assert_eq!(content_type_header.value, "application/json");

        let server_header = response
            .headers
            .get("Server")
            .expect("Server header should exist");
        assert_eq!(server_header.range, 47..68);
        assert_eq!(server_header.value, "nginx/1.18.0");

        let date_header = response
            .headers
            .get("Date")
            .expect("Date header should exist");
        assert_eq!(date_header.range, 68..104);
        assert_eq!(date_header.value, "Mon, 01 Jan 2024 00:00:00 GMT");
    }

    #[test]
    fn test_parse_response_with_nested_json() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

3d
{"user":{"name":"Alice", "profile":{"age":30}}}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("user"));
                match &value["user"] {
                    RangedValue::Object {
                        value: user_obj, ..
                    } => {
                        assert!(user_obj.contains_key("name"));
                        assert!(user_obj.contains_key("profile"));
                    }
                    _ => panic!("Expected nested user object"),
                }
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_parse_response_with_array() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

1e
[{"id":1}, {"id":2}, {"id":3}]
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Array { value, .. } => {
                assert_eq!(value.len(), 3);
            }
            _ => panic!("Expected array content"),
        }
    }

    #[test]
    fn test_parse_response_with_primitive_values() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

28
{"string":"test", "number":42, "bool":true, "null":null}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => {
                // Check string value
                match &value["string"] {
                    RangedValue::String { value: v, .. } => assert_eq!(v, "test"),
                    _ => panic!("Expected string"),
                }

                // Check number value
                match &value["number"] {
                    RangedValue::Number { value: v, .. } => assert_eq!(*v, 42.0),
                    _ => panic!("Expected number"),
                }

                // Check boolean value
                match &value["bool"] {
                    RangedValue::Bool { value: v, .. } => assert!(v),
                    _ => panic!("Expected boolean"),
                }

                // Check null value
                match &value["null"] {
                    RangedValue::Null => (),
                    _ => panic!("Expected null"),
                }
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_response_range_tracking() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

f
{"id":123}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();

        for header in response.headers.values() {
            assert!(header.range.start < header.range.end);
        }

        let range = response.body.get_range();
        assert!(range.start < range.end);
    }

    #[test]
    fn test_parse_response_with_special_header_chars() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Set-Cookie: session=abc123; Path=/; HttpOnly

e
{"ok":true}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();

        let content_type_header = response
            .headers
            .get("Content-Type")
            .expect("Content-Type header should exist");
        assert_eq!(content_type_header.range, 16..62);
        assert_eq!(content_type_header.value, "application/json; charset=utf-8");

        let set_cookie_header = response
            .headers
            .get("Set-Cookie")
            .expect("Set-Cookie header should exist");
        assert_eq!(set_cookie_header.range, 62..107);
        assert_eq!(set_cookie_header.value, "session=abc123; Path=/; HttpOnly");
    }

    #[test]
    fn test_search_response_headers() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json
Server: nginx

d
{"id":1}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();
        let header_ranges = response
            .get_header_ranges(&["Content-Type", "Server"])
            .unwrap();

        assert_eq!(header_ranges.len(), 2);
    }

    #[test]
    fn test_search_response_keypaths() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

2a
{"user":{"name":"Bob", "email":"bob@example.com"}}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();
        let body_ranges = response
            .get_body_keypaths_ranges(&["user.name", "user.email"])
            .unwrap();

        assert_eq!(body_ranges.len(), 2);
    }

    #[test]
    fn test_search_nested_array_keypaths() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

2f
{"items":[{"id":1, "name":"Item1"}, {"id":2, "name":"Item2"}]}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();
        let body_ranges = response.get_body_keypaths_ranges(&["items"]).unwrap();

        assert_eq!(body_ranges.len(), 1);
    }

    #[test]
    fn test_empty_response_object() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

2
{}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.is_empty());
            }
            _ => panic!("Expected empty object"),
        }
    }

    #[test]
    fn test_empty_response_array() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

2
[]
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Array { value, .. } => {
                assert!(value.is_empty());
            }
            _ => panic!("Expected empty array"),
        }
    }

    #[test]
    fn test_response_with_escaped_strings() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

1f
{"message":"Hello\nWorld\t!"}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("message"));
            }
            _ => panic!("Expected object"),
        }
    }

    #[test]
    fn test_response_with_unicode() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

15
{"emoji":"🚀"}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_response_with_negative_numbers() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

1a
{"temp":-15.5, "balance":-100}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => match &value["temp"] {
                RangedValue::Number { value: v, .. } => assert_eq!(*v, -15.5),
                _ => panic!("Expected negative number"),
            },
            _ => panic!("Expected object"),
        }
    }

    #[test]
    fn test_response_with_scientific_notation() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

14
{"value":1.5e10}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => match &value["value"] {
                RangedValue::Number { value: v, .. } => assert_eq!(*v, 1.5e10),
                _ => panic!("Expected scientific notation number"),
            },
            _ => panic!("Expected object"),
        }
    }

    #[test]
    fn test_response_with_content_length_encoding() {
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 34

{"username":"alice","balance":100}"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.headers.len(), 2);

        let content_type_header = response
            .headers
            .get("Content-Type")
            .expect("Content-Type header should exist");
        assert_eq!(content_type_header.value, "application/json");

        let content_length_header = response
            .headers
            .get("Content-Length")
            .expect("Content-Length header should exist");
        assert_eq!(content_length_header.value, "34");

        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("username"));
                assert!(value.contains_key("balance"));
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_response_with_content_length_and_crlf() {
        let input = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 34\r\n\r\n{\"username\":\"alice\",\"balance\":100}";

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.headers.len(), 2);

        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("username"));
                assert!(value.contains_key("balance"));
            }
            _ => panic!("Expected object content"),
        }
    }

    #[test]
    fn test_chunked_encoding_still_works() {
        // Ensure chunked encoding still works after our changes
        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

22
{"username":"bob","balance":200}
0
"#;

        let result = ResponseParser::parse_response(input);
        assert!(result.is_ok());

        let response = result.unwrap();
        match &response.body {
            RangedValue::Object { value, .. } => {
                assert!(value.contains_key("username"));
                assert!(value.contains_key("balance"));
            }
            _ => panic!("Expected object content"),
        }
    }
}
