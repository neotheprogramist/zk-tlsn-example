use super::{RedactedRequestParser, RedactedResponseParser};
use crate::ranged::RangedValue;

#[test]
fn test_redacted_request_full_flow() {
    shared::init_test_logging();

    let input = "GET /api/balance/alice HTTP/1.1\r\ncontent-type: application/json\r\nauthorization: Bearer token123\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    let request = RedactedRequestParser::parse_redacted_request(input).unwrap();

    assert_eq!(
        &input[request.request_line.range.clone()],
        "GET /api/balance/alice HTTP/1.1\r\n"
    );
    assert_eq!(
        request.request_line.value,
        "GET /api/balance/alice HTTP/1.1"
    );

    assert_eq!(request.headers.len(), 2);

    let content_type_header = request
        .headers
        .get("content-type")
        .expect("content-type header should exist")
        .to_owned();
    assert_eq!(
        &input[content_type_header.range.clone()],
        "content-type: application/json\r\n"
    );
    assert_eq!(content_type_header.value, "application/json");

    let auth_header = request
        .headers
        .get("authorization")
        .expect("authorization header should exist")
        .to_owned();
    assert_eq!(
        &input[auth_header.range.clone()],
        "authorization: Bearer token123\r\n"
    );
    assert_eq!(auth_header.value, "Bearer token123");

    assert_eq!(request.body.len(), 0);
}

#[test]
fn test_redacted_response_full_flow() {
    shared::init_test_logging();

    let input = "HTTP/1.1 200 OK\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\"username\":\"alice\"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    let response = RedactedResponseParser::parse_redacted_response(input).unwrap();

    assert_eq!(
        &input[response.status_line.range.clone()],
        "HTTP/1.1 200 OK\r\n"
    );
    assert_eq!(response.status_line.value, "HTTP/1.1 200 OK");

    assert_eq!(response.headers.len(), 0);

    assert_eq!(response.body.len(), 1);

    let username_value = response
        .body
        .get("username")
        .expect("username field should exist");

    match username_value {
        RangedValue::String { range, value } => {
            assert_eq!(&input[range.clone()], "\"username\":\"alice\"");
            assert_eq!(value, "alice");
        }
        _ => panic!("username should be a string value"),
    }
}

#[test]
fn test_redacted_response_multiple_fields() {
    shared::init_test_logging();

    let input = "HTTP/1.1 200 OK\r\n\0\0\0\0\"username\":\"alice\"\0\0\"balance\":\"100\"\0\0\0";

    let response = RedactedResponseParser::parse_redacted_response(input).unwrap();

    assert_eq!(
        &input[response.status_line.range.clone()],
        "HTTP/1.1 200 OK\r\n"
    );
    assert_eq!(response.status_line.value, "HTTP/1.1 200 OK");

    assert_eq!(response.body.len(), 2);

    let username_value = response
        .body
        .get("username")
        .expect("username field should exist");
    match username_value {
        RangedValue::String { range, value } => {
            assert_eq!(&input[range.clone()], "\"username\":\"alice\"");
            assert_eq!(value, "alice");
        }
        _ => panic!("username should be a string value"),
    }

    let balance_value = response
        .body
        .get("balance")
        .expect("balance field should exist");
    match balance_value {
        RangedValue::String { range, value } => {
            assert_eq!(&input[range.clone()], "\"balance\":\"100\"");
            assert_eq!(value, "100");
        }
        _ => panic!("balance should be a string value"),
    }
}

#[test]
fn test_redacted_with_headers_and_body() {
    shared::init_test_logging();

    let input = "HTTP/1.1 200 OK\r\nserver: nginx\r\n\0\0\0\"status\":\"ok\"\0\0\0";

    let response = RedactedResponseParser::parse_redacted_response(input).unwrap();

    assert_eq!(
        &input[response.status_line.range.clone()],
        "HTTP/1.1 200 OK\r\n"
    );
    assert_eq!(response.status_line.value, "HTTP/1.1 200 OK");

    assert_eq!(response.headers.len(), 1);

    let server_header = response
        .headers
        .get("server")
        .expect("server header should exist")
        .to_owned();
    assert_eq!(&input[server_header.range.clone()], "server: nginx\r\n");
    assert_eq!(server_header.value, "nginx");

    assert_eq!(response.body.len(), 1);

    let status_value = response
        .body
        .get("status")
        .expect("status field should exist");
    match status_value {
        RangedValue::String { range, value } => {
            assert_eq!(&input[range.clone()], "\"status\":\"ok\"");
            assert_eq!(value, "ok");
        }
        _ => panic!("status should be a string value"),
    }
}
