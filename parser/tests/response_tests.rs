use parser::{BodySearchable, HeaderSearchable, RangedValue, ResponseParser};

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
    assert!(response.headers.contains_key("Content-Type"));
    assert_eq!(response.headers["Content-Type"].value, "application/json");

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
    assert!(response.headers.contains_key("Content-Type"));
    assert!(response.headers.contains_key("Server"));
    assert!(response.headers.contains_key("Date"));
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

    for (_, header) in &response.headers {
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
    assert!(response.headers.contains_key("Content-Type"));
    assert!(response.headers.contains_key("Set-Cookie"));
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
    let header_ranges = response.get_header_ranges(&["Content-Type", "Server"]);

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
    let body_ranges = response.get_body_keypaths_ranges(&["user.name", "user.email"]);

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
    let body_ranges = response.get_body_keypaths_ranges(&["items"]);

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
