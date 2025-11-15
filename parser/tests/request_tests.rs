use parser::{HeaderSearchable, RangedValue, RequestParser};

#[test]
fn test_parse_simple_get_request() {
    let input = "GET /api/users HTTP/1.1\nHost: example.com\n\n";
    let result = RequestParser::parse_request(input);

    if let Err(e) = &result {
        eprintln!("Parse error: {:?}", e);
    }
    assert!(result.is_ok());
    let request = result.unwrap();

    assert!(
        request
            .request_line
            .value
            .starts_with("GET /api/users HTTP/1.1")
    );
    assert_eq!(request.request_line.range.start, 0);

    assert_eq!(request.headers.len(), 1);
    assert!(request.headers.contains_key("Host"));
    assert_eq!(request.headers["Host"].value, "example.com");

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

    assert!(request.request_line.value.contains("POST"));

    assert_eq!(request.headers.len(), 2);
    assert!(request.headers.contains_key("Host"));
    assert!(request.headers.contains_key("Content-Type"));

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
    assert!(request.headers.contains_key("Host"));
    assert!(request.headers.contains_key("User-Agent"));
    assert!(request.headers.contains_key("Accept"));
    assert!(request.headers.contains_key("Authorization"));
}

#[test]
fn test_parse_request_with_special_chars_in_url() {
    let input = "GET /api/search?q=hello%20world&page=1 HTTP/1.1\nHost: example.com\n\n";
    let result = RequestParser::parse_request(input);

    assert!(result.is_ok());
    let request = result.unwrap();
    assert!(
        request
            .request_line
            .value
            .contains("/api/search?q=hello%20world&page=1")
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

    for (_, header) in &request.headers {
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
    let header_ranges = request.get_header_ranges(&["Host", "Content-Type"]);

    assert_eq!(header_ranges.len(), 2);
}

#[test]
fn test_search_request_keypaths() {
    let input = r#"POST /api/users HTTP/1.1
Host: example.com

{"user":{"name":"Alice", "age":30}}"#;

    let request = RequestParser::parse_request(input).unwrap();
    let body_ranges = request.get_body_keypaths_ranges(&["user.name"]);

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
        assert!(request.request_line.value.contains(method));
    }
}
