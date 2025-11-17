use super::{RequestParser, ResponseParser};
use crate::{
    ranged::RangedValue,
    search::{BodySearchable, HeaderSearchable},
};

#[test]
fn test_request_full_flow() {
    shared::init_test_logging();

    let input = r#"POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
User-Agent: TestClient/1.0

{"user":{"name":"Alice","email":"alice@example.com","age":30}}"#;

    let request = RequestParser::parse_request(input).unwrap();

    let request_line_range = request.get_request_line_range();
    assert_eq!(
        &input[request_line_range.clone()],
        "POST /api/users HTTP/1.1\n"
    );
    assert_eq!(request.request_line.value, "POST /api/users HTTP/1.1\n");

    assert_eq!(request.headers.len(), 3);

    let host_header = request
        .headers
        .get("Host")
        .expect("Host header should exist")
        .to_owned();
    assert_eq!(&input[host_header.range.clone()], "Host: api.example.com\n");
    assert_eq!(host_header.value, "api.example.com");

    let content_type_header = request
        .headers
        .get("Content-Type")
        .expect("Content-Type header should exist")
        .to_owned();
    assert_eq!(
        &input[content_type_header.range.clone()],
        "Content-Type: application/json\n"
    );
    assert_eq!(content_type_header.value, "application/json");

    let user_agent_header = request
        .headers
        .get("User-Agent")
        .expect("User-Agent header should exist")
        .to_owned();
    assert_eq!(
        &input[user_agent_header.range.clone()],
        "User-Agent: TestClient/1.0\n"
    );
    assert_eq!(user_agent_header.value, "TestClient/1.0");

    let body_ranges = request
        .get_body_keypaths_ranges(&["user.name", "user.email", "user.age"])
        .unwrap();
    assert_eq!(body_ranges.len(), 3);
    assert_eq!(&input[body_ranges[0].clone()], "\"name\":\"Alice\"");
    assert_eq!(
        &input[body_ranges[1].clone()],
        "\"email\":\"alice@example.com\""
    );
    assert_eq!(&input[body_ranges[2].clone()], "\"age\":30");

    let header_ranges = request
        .get_header_ranges(&["Host", "Content-Type"])
        .unwrap();
    assert_eq!(header_ranges.len(), 2);
    assert_eq!(&input[header_ranges[0].clone()], "Host: api.example.com\n");
    assert_eq!(
        &input[header_ranges[1].clone()],
        "Content-Type: application/json\n"
    );
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

    let response = ResponseParser::parse_response(input).unwrap();

    let status_line_range = response.get_status_line_range();
    assert_eq!(&input[status_line_range.clone()], "HTTP/1.1 200 OK\n");
    assert_eq!(response.status_line.value, "HTTP/1.1 200 OK");

    assert_eq!(response.headers.len(), 3);

    let content_type_header = response
        .headers
        .get("Content-Type")
        .expect("Content-Type header should exist")
        .to_owned();
    assert_eq!(
        &input[content_type_header.range.clone()],
        "Content-Type: application/json\n"
    );
    assert_eq!(content_type_header.value, "application/json");

    let server_header = response
        .headers
        .get("Server")
        .expect("Server header should exist")
        .to_owned();
    assert_eq!(
        &input[server_header.range.clone()],
        "Server: nginx/1.18.0\n"
    );
    assert_eq!(server_header.value, "nginx/1.18.0");

    let date_header = response
        .headers
        .get("Date")
        .expect("Date header should exist")
        .to_owned();
    assert_eq!(
        &input[date_header.range.clone()],
        "Date: Mon, 01 Jan 2024 00:00:00 GMT\n"
    );
    assert_eq!(date_header.value, "Mon, 01 Jan 2024 00:00:00 GMT");

    let body_ranges = response
        .get_body_keypaths_ranges(&["status", "data.users[0].id", "data.users[1].id"])
        .unwrap();
    assert_eq!(body_ranges.len(), 3);
    assert_eq!(&input[body_ranges[0].clone()], "\"status\":\"success\"");
    assert_eq!(&input[body_ranges[1].clone()], "\"id\":1");
    assert_eq!(&input[body_ranges[2].clone()], "\"id\":2");

    let header_ranges = response
        .get_header_ranges(&["Content-Type", "Server"])
        .unwrap();
    assert_eq!(header_ranges.len(), 2);
    assert_eq!(
        &input[header_ranges[0].clone()],
        "Content-Type: application/json\n"
    );
    assert_eq!(&input[header_ranges[1].clone()], "Server: nginx/1.18.0\n");
}

#[test]
fn test_request_without_body() {
    shared::init_test_logging();

    let input = "GET /api/test HTTP/1.1\nHost: example.com\nAuthorization: Bearer token123\n\n";

    let request = RequestParser::parse_request(input).unwrap();

    let request_line_range = request.get_request_line_range();
    assert_eq!(
        &input[request_line_range.clone()],
        "GET /api/test HTTP/1.1\n"
    );
    assert_eq!(request.request_line.value, "GET /api/test HTTP/1.1\n");

    assert_eq!(request.headers.len(), 2);

    let host_header = request
        .headers
        .get("Host")
        .expect("Host header should exist")
        .to_owned();
    assert_eq!(&input[host_header.range.clone()], "Host: example.com\n");
    assert_eq!(host_header.value, "example.com");

    let auth_header = request
        .headers
        .get("Authorization")
        .expect("Authorization header should exist")
        .to_owned();
    assert_eq!(
        &input[auth_header.range.clone()],
        "Authorization: Bearer token123\n"
    );
    assert_eq!(auth_header.value, "Bearer token123");

    assert!(request.body.is_none());

    let result = request.get_body_keypaths_ranges(&["any.path"]);
    assert!(result.is_err());
}

#[test]
fn test_array_and_nested_structures() {
    shared::init_test_logging();

    let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

50
{"matrix":[[1,2],[3,4]],"nested":{"array":[{"key":"value"}]}}
0
"#;

    let response = ResponseParser::parse_response(input).unwrap();

    assert_eq!(response.status_line.value, "HTTP/1.1 200 OK");

    let body_ranges = response
        .get_body_keypaths_ranges(&["matrix[0][0]", "matrix[1][1]", "nested.array[0].key"])
        .unwrap();
    assert_eq!(body_ranges.len(), 3);
    assert_eq!(&input[body_ranges[0].clone()], "1");
    assert_eq!(&input[body_ranges[1].clone()], "4");
    assert_eq!(&input[body_ranges[2].clone()], "\"key\":\"value\"");

    match &response.body {
        RangedValue::Object { value, .. } => {
            let matrix = value.get("matrix").expect("matrix field should exist");
            match matrix {
                RangedValue::Array { value: arr, .. } => {
                    assert_eq!(arr.len(), 2);
                }
                _ => panic!("matrix should be an array"),
            }
        }
        _ => panic!("body should be an object"),
    }
}
