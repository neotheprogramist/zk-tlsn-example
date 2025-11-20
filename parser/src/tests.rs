use std::{ops::Range, str::FromStr};

use crate::{
    redacted, standard,
    traits::{HttpBody, HttpHeader},
};

fn redact_string(input: &str, keep_ranges: &[Range<usize>]) -> String {
    let mut bytes = input.as_bytes().to_vec();

    let mut keep_mask = vec![false; bytes.len()];
    for range in keep_ranges {
        for i in range.clone() {
            keep_mask[i] = true;
        }
    }

    for (i, byte) in bytes.iter_mut().enumerate() {
        if !keep_mask[i] {
            *byte = b'\0';
        }
    }

    String::from_utf8(bytes).expect("Invalid UTF-8 after redaction")
}

#[test]
fn test_request_full_flow() {
    shared::init_test_logging();

    let input = r#"POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
User-Agent: TestClient/1.0

3e
{"user":{"name":"Alice","email":"alice@example.com","age":30}}
0
"#;

    let request = standard::Request::from_str(input).unwrap();

    assert_eq!(&input[request.method.clone()], "POST");

    assert_eq!(&input[request.url.clone()], "/api/users");

    assert_eq!(&input[request.protocol_version.clone()], "HTTP/1.1");

    assert_eq!(request.headers.len(), 3);

    let host_headers = request
        .headers
        .get("host")
        .expect("Host header should exist");
    assert_eq!(host_headers.len(), 1);
    let host_header = &host_headers[0];
    assert_eq!(&input[host_header.name.clone()], "Host");
    assert_eq!(&input[host_header.value.clone()], "api.example.com");

    let content_type_headers = request
        .headers
        .get("content-type")
        .expect("Content-Type header should exist");
    assert_eq!(content_type_headers.len(), 1);
    let content_type_header = &content_type_headers[0];
    assert_eq!(&input[content_type_header.name.clone()], "Content-Type");
    assert_eq!(
        &input[content_type_header.value.clone()],
        "application/json"
    );

    let user_agent_headers = request
        .headers
        .get("user-agent")
        .expect("User-Agent header should exist");
    assert_eq!(user_agent_headers.len(), 1);
    let user_agent_header = &user_agent_headers[0];
    assert_eq!(&input[user_agent_header.name.clone()], "User-Agent");
    assert_eq!(&input[user_agent_header.value.clone()], "TestClient/1.0");

    let root_body = request.body.get("").expect("Root body should exist");
    match root_body {
        standard::Body::Value(range) => {
            assert_eq!(
                &input[range.clone()],
                r#"{"user":{"name":"Alice","email":"alice@example.com","age":30}}"#
            );
        }
        _ => panic!("Root body should be a Value"),
    }

    let user_field = request.body.get(".user").expect(".user field should exist");
    match user_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "user");
            assert_eq!(
                &input[value.clone()],
                r#"{"name":"Alice","email":"alice@example.com","age":30}"#
            );
        }
        _ => panic!(".user should be a KeyValue"),
    }

    let name_field = request
        .body
        .get(".user.name")
        .expect(".user.name field should exist");
    match name_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "name");
            assert_eq!(&input[value.clone()], "Alice");
        }
        _ => panic!(".user.name should be a KeyValue"),
    }

    let email_field = request
        .body
        .get(".user.email")
        .expect(".user.email field should exist");
    match email_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "email");
            assert_eq!(&input[value.clone()], "alice@example.com");
        }
        _ => panic!(".user.email should be a KeyValue"),
    }

    let age_field = request
        .body
        .get(".user.age")
        .expect(".user.age field should exist");
    match age_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "age");
            assert_eq!(&input[value.clone()], "30");
        }
        _ => panic!(".user.age should be a KeyValue"),
    }
}

#[test]
fn test_response_full_flow() {
    shared::init_test_logging();

    let input = r#"HTTP/1.1 200 OK
Content-Type: application/json
Server: nginx/1.18.0
Date: Mon, 01 Jan 2024 00:00:00 GMT

3e
{"status":"success","data":{"users":[{"id":1},{"id":2}]}}
0
"#;

    let response = standard::Response::from_str(input).unwrap();

    assert_eq!(&input[response.protocol_version.clone()], "HTTP/1.1");

    assert_eq!(&input[response.status_code.clone()], "200");

    assert_eq!(&input[response.status.clone()], "OK");

    assert_eq!(response.headers.len(), 3);

    let content_type_headers = response
        .headers
        .get("content-type")
        .expect("Content-Type header should exist");
    assert_eq!(content_type_headers.len(), 1);
    let content_type_header = &content_type_headers[0];
    assert_eq!(&input[content_type_header.name.clone()], "Content-Type");
    assert_eq!(
        &input[content_type_header.value.clone()],
        "application/json"
    );

    let server_headers = response
        .headers
        .get("server")
        .expect("Server header should exist");
    assert_eq!(server_headers.len(), 1);
    let server_header = &server_headers[0];
    assert_eq!(&input[server_header.name.clone()], "Server");
    assert_eq!(&input[server_header.value.clone()], "nginx/1.18.0");

    let date_headers = response
        .headers
        .get("date")
        .expect("Date header should exist");
    assert_eq!(date_headers.len(), 1);
    let date_header = &date_headers[0];
    assert_eq!(&input[date_header.name.clone()], "Date");
    assert_eq!(
        &input[date_header.value.clone()],
        "Mon, 01 Jan 2024 00:00:00 GMT"
    );

    let root_body = response.body.get("").expect("Root body should exist");
    match root_body {
        standard::Body::Value(range) => {
            assert_eq!(
                &input[range.clone()],
                r#"{"status":"success","data":{"users":[{"id":1},{"id":2}]}}"#
            );
        }
        _ => panic!("Root body should be a Value"),
    }

    let status_field = response
        .body
        .get(".status")
        .expect(".status field should exist");
    match status_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "status");
            assert_eq!(&input[value.clone()], "success");
        }
        _ => panic!(".status should be a KeyValue"),
    }

    let data_field = response
        .body
        .get(".data")
        .expect(".data field should exist");
    match data_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "data");
            assert_eq!(&input[value.clone()], r#"{"users":[{"id":1},{"id":2}]}"#);
        }
        _ => panic!(".data should be a KeyValue"),
    }

    let users_field = response
        .body
        .get(".data.users")
        .expect(".data.users field should exist");
    match users_field {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "users");
            assert_eq!(&input[value.clone()], r#"[{"id":1},{"id":2}]"#);
        }
        _ => panic!(".data.users should be a KeyValue"),
    }

    let user0 = response
        .body
        .get(".data.users[0]")
        .expect(".data.users[0] should exist");
    match user0 {
        standard::Body::Value(range) => {
            assert_eq!(&input[range.clone()], r#"{"id":1}"#);
        }
        _ => panic!(".data.users[0] should be a Value"),
    }

    let user0_id = response
        .body
        .get(".data.users[0].id")
        .expect(".data.users[0].id should exist");
    match user0_id {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "id");
            assert_eq!(&input[value.clone()], "1");
        }
        _ => panic!(".data.users[0].id should be a KeyValue"),
    }

    let user1 = response
        .body
        .get(".data.users[1]")
        .expect(".data.users[1] should exist");
    match user1 {
        standard::Body::Value(range) => {
            assert_eq!(&input[range.clone()], r#"{"id":2}"#);
        }
        _ => panic!(".data.users[1] should be a Value"),
    }

    let user1_id = response
        .body
        .get(".data.users[1].id")
        .expect(".data.users[1].id should exist");
    match user1_id {
        standard::Body::KeyValue { key, value } => {
            assert_eq!(&input[key.clone()], "id");
            assert_eq!(&input[value.clone()], "2");
        }
        _ => panic!(".data.users[1].id should be a KeyValue"),
    }
}

#[test]
fn test_redacted_request_full_flow() {
    shared::init_test_logging();

    let input = r#"POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
User-Agent: TestClient/1.0

3e
{"user":{"name":"Alice","email":"alice@example.com","age":30}}
0
"#;

    let standard_request = standard::Request::from_str(input).unwrap();

    let mut keep_ranges = vec![
        standard_request.method_with_space(),
        standard_request.url_with_space(),
        standard_request.protocol_version_with_newline(),
    ];

    let host_header = &standard_request.headers.get("host").unwrap()[0];
    keep_ranges.push(host_header.name_with_separator());
    keep_ranges.push(host_header.value_with_newline());

    let user_agent_header = &standard_request.headers.get("user-agent").unwrap()[0];
    keep_ranges.push(user_agent_header.name_with_separator());

    let name_field = standard_request.body.get(".user.name").unwrap();
    keep_ranges.push(name_field.key_with_quotes_and_colon().unwrap());
    keep_ranges.push(name_field.value_with_quotes());

    let email_field = standard_request.body.get(".user.email").unwrap();
    keep_ranges.push(email_field.key_with_quotes_and_colon().unwrap());
    keep_ranges.push(email_field.value_with_quotes());

    let age_field = standard_request.body.get(".user.age").unwrap();
    keep_ranges.push(age_field.key_with_quotes_and_colon().unwrap());

    let redacted_input = redact_string(input, &keep_ranges);

    let redacted_request = redacted::Request::from_str(&redacted_input).unwrap();

    assert_eq!(&redacted_input[redacted_request.method.clone()], "POST");
    assert_eq!(&redacted_input[redacted_request.url.clone()], "/api/users");
    assert_eq!(
        &redacted_input[redacted_request.protocol_version.clone()],
        "HTTP/1.1"
    );

    assert_eq!(redacted_request.headers.len(), 2);

    let host_headers = redacted_request
        .headers
        .get("host")
        .expect("Host header should exist");
    assert_eq!(host_headers.len(), 1);
    let host_header = &host_headers[0];
    assert_eq!(&redacted_input[host_header.name.clone()], "Host");
    assert_eq!(
        &redacted_input[host_header.value.clone().unwrap()],
        "api.example.com"
    );

    let user_agent_headers = redacted_request
        .headers
        .get("user-agent")
        .expect("User-Agent header should exist");
    assert_eq!(user_agent_headers.len(), 1);
    let user_agent_header = &user_agent_headers[0];
    assert_eq!(
        &redacted_input[user_agent_header.name.clone()],
        "User-Agent"
    );
    assert!(
        user_agent_header.value.is_none(),
        "User-Agent header value should be None"
    );

    let name_field = redacted_request
        .body
        .get(".name")
        .expect(".name field should exist");
    match name_field {
        redacted::Body::KeyValue {
            key,
            value: Some(value),
        } => {
            assert_eq!(&redacted_input[key.clone()], "name");
            assert_eq!(&redacted_input[value.clone()], "Alice");
        }
        _ => panic!(".name should be a KeyValue"),
    }

    let email_field = redacted_request
        .body
        .get(".email")
        .expect(".email field should exist");
    match email_field {
        redacted::Body::KeyValue {
            key,
            value: Some(value),
        } => {
            assert_eq!(&redacted_input[key.clone()], "email");
            assert_eq!(&redacted_input[value.clone()], "alice@example.com");
        }
        _ => panic!(".email should be a KeyValue"),
    }

    let age_field = redacted_request
        .body
        .get(".age")
        .expect(".age field should exist");
    match age_field {
        redacted::Body::KeyValue { key, value } => {
            assert_eq!(&redacted_input[key.clone()], "age");
            assert!(value.is_none(), "age field value should be None");
        }
        _ => panic!(".age should be a KeyValue"),
    }
}

#[test]
fn test_redacted_response_full_flow() {
    shared::init_test_logging();

    let input = r#"HTTP/1.1 200 OK
Content-Type: application/json
Server: nginx/1.18.0
Date: Mon, 01 Jan 2024 00:00:00 GMT

3e
{"status":"success","data":{"users":[{"id":1},{"id":2}]}}
0
"#;

    let standard_response = standard::Response::from_str(input).unwrap();

    let mut keep_ranges = vec![
        standard_response.protocol_version_with_space(),
        standard_response.status_code_with_space(),
        standard_response.status_with_newline(),
    ];

    let server_header = &standard_response.headers.get("server").unwrap()[0];
    keep_ranges.push(server_header.name_with_separator());
    keep_ranges.push(server_header.value_with_newline());

    let content_type_header = &standard_response.headers.get("content-type").unwrap()[0];
    keep_ranges.push(content_type_header.name_with_separator());

    let status_field = standard_response.body.get(".status").unwrap();
    keep_ranges.push(status_field.key_with_quotes_and_colon().unwrap());
    keep_ranges.push(status_field.value_with_quotes());

    if let standard::Body::Value(value) = standard_response.body.get(".data.users[0]").unwrap() {
        keep_ranges.push(value.start + 1..value.end - 1);
    }

    let data_field = standard_response.body.get(".data").unwrap();
    keep_ranges.push(data_field.key_with_quotes_and_colon().unwrap());

    let redacted_input = redact_string(input, &keep_ranges);

    let redacted_response = redacted::Response::from_str(&redacted_input).unwrap();

    assert_eq!(
        &redacted_input[redacted_response.protocol_version.clone()],
        "HTTP/1.1"
    );
    assert_eq!(
        &redacted_input[redacted_response.status_code.clone()],
        "200"
    );
    assert_eq!(&redacted_input[redacted_response.status.clone()], "OK");

    assert_eq!(redacted_response.headers.len(), 2);

    let server_headers = redacted_response
        .headers
        .get("server")
        .expect("Server header should exist");
    assert_eq!(server_headers.len(), 1);
    let server_header = &server_headers[0];
    assert_eq!(&redacted_input[server_header.name.clone()], "Server");
    assert_eq!(
        &redacted_input[server_header.value.clone().unwrap()],
        "nginx/1.18.0"
    );

    let content_type_headers = redacted_response
        .headers
        .get("content-type")
        .expect("Content-Type header should exist");
    assert_eq!(content_type_headers.len(), 1);
    let content_type_header = &content_type_headers[0];
    assert_eq!(
        &redacted_input[content_type_header.name.clone()],
        "Content-Type"
    );
    assert!(
        content_type_header.value.is_none(),
        "Content-Type header value should be None"
    );

    let status_field = redacted_response
        .body
        .get(".status")
        .expect(".status field should exist");
    match status_field {
        redacted::Body::KeyValue {
            key,
            value: Some(value),
        } => {
            assert_eq!(&redacted_input[key.clone()], "status");
            assert_eq!(&redacted_input[value.clone()], "success");
        }
        _ => panic!(".status should be a KeyValue"),
    }

    let id_field = redacted_response
        .body
        .get(".id")
        .expect(".id field should exist");
    match id_field {
        redacted::Body::KeyValue {
            key,
            value: Some(value),
        } => {
            assert_eq!(&redacted_input[key.clone()], "id");
            assert_eq!(&redacted_input[value.clone()], "1");
        }
        _ => panic!(".id should be a KeyValue"),
    }

    let data_field = redacted_response
        .body
        .get(".data")
        .expect(".data field should exist");
    match data_field {
        redacted::Body::KeyValue { key, value } => {
            assert_eq!(&redacted_input[key.clone()], "data");
            assert!(value.is_none(), "data field value should be None");
        }
        _ => panic!(".data should be a KeyValue"),
    }
}
