//! HTTP Request/Response Parser with Range Tracking
//!
//! This crate provides parsers for HTTP requests and responses that track
//! the byte ranges of all parsed elements in the original input. This is
//! useful for applications that need to reference specific parts of the
//! HTTP message, such as selective disclosure in TLS proofs.
//!
//! # JSONPath Syntax
//!
//! **Important:** This parser uses a **simplified keypath syntax** that is
//! intentionally divergent from RFC 9535 (JSONPath). The simplified syntax
//! is designed specifically for TLS notarization use cases where:
//! - Precise byte ranges for known field paths are required
//! - Wildcards and filters would complicate range extraction
//! - Security-critical code benefits from minimal complexity
//!
//! **Supported syntax:**
//! - Object keys: `"field"`, `"nested.field"`, `"deeply.nested.field"`
//! - Array indexing: `"[0]"`, `"items[0]"`, `"users[1].name"`
//! - Nested arrays: `"matrix[0][1]"`, `"data[0].values[2]"`
//!
//! **Not supported:** RFC 9535 features like `$` root identifier, bracket notation
//! for keys `$['field']`, negative indexing `$[-1]`, array slicing `$[1:3]`,
//! wildcards `[*]`, recursive descent `..`, or filter expressions `?<expr>`.
//!
//! See [`BodySearchable::get_body_keypaths_ranges`] for detailed documentation.
//!
//! # Examples
//!
//! ## Complete End-to-End Flow
//!
//! ```
//! use parser::{BodySearchable, HeaderSearchable, RequestParser, ResponseParser};
//!
//! // Parse an HTTP request with JSON body
//! let request_str = r#"POST /api/users HTTP/1.1
//! Host: example.com
//! Content-Type: application/json
//!
//! {"user":{"name":"Alice","email":"alice@example.com"}}"#;
//!
//! let request = RequestParser::parse_request(request_str).unwrap();
//!
//! // Get the range of the request line
//! let request_line_range = request.get_request_line_range();
//! let request_line_text = &request_str[request_line_range];
//! assert!(request_line_text.starts_with("POST /api/users HTTP/1.1"));
//!
//! // Get ranges for specific headers (returns error if header not found)
//! let header_ranges = request
//!     .get_header_ranges(&["Host", "Content-Type"])
//!     .unwrap();
//! assert_eq!(header_ranges.len(), 2);
//!
//! // Extract header values using ranges
//! for range in &header_ranges {
//!     let header_text = &request_str[range.clone()];
//!     println!("Header: {}", header_text);
//! }
//!
//! // Get ranges for specific JSON keypaths in the body (returns error if keypath not found)
//! let body_ranges = request
//!     .get_body_keypaths_ranges(&["user.name", "user.email"])
//!     .unwrap();
//! assert_eq!(body_ranges.len(), 2);
//!
//! // Extract specific JSON values using ranges
//! for range in &body_ranges {
//!     let value_text = &request_str[range.clone()];
//!     println!("Value: {}", value_text);
//! }
//!
//! // Parse an HTTP response with chunked encoding
//! let response_str = r#"HTTP/1.1 200 OK
//! Content-Type: application/json
//! Server: nginx/1.18.0
//!
//! 2d
//! {"status":"success","data":{"id":123}}
//! 0
//! "#;
//!
//! let response = ResponseParser::parse_response(response_str).unwrap();
//!
//! // Get ranges for response headers (returns error if header not found)
//! let resp_header_ranges = response
//!     .get_header_ranges(&["Content-Type", "Server"])
//!     .unwrap();
//! assert_eq!(resp_header_ranges.len(), 2);
//!
//! // Get ranges for nested JSON paths in response body (returns error if keypath not found)
//! let resp_body_ranges = response
//!     .get_body_keypaths_ranges(&["status", "data.id"])
//!     .unwrap();
//! assert_eq!(resp_body_ranges.len(), 2);
//!
//! // Extract the specific data using ranges
//! for range in &resp_body_ranges {
//!     let data_text = &response_str[range.clone()];
//!     println!("Response data: {}", data_text);
//! }
//! ```

mod error;
mod grammar;
mod search;
mod types;

// Re-export public API
pub use error::ParserError;
pub use grammar::{RedactedRequestParser, RedactedResponseParser, RequestParser, ResponseParser};
pub use search::{BodySearchable, HeaderSearchable};
pub use types::{RangedText, RangedValue, Request, Response};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_parsing_and_range_extraction() {
        shared::init_test_logging();

        let input = r#"POST /api/users HTTP/1.1
Host: example.com
Content-Type: application/json

{"name":"Alice","age":30}"#;

        let request = RequestParser::parse_request(input).unwrap();

        // Test request line with exact range and value
        let request_line_range = request.get_request_line_range();
        assert_eq!(request_line_range, 0..25);
        assert_eq!(&input[request_line_range], "POST /api/users HTTP/1.1\n");

        // Test header extraction with exact ranges and values
        let header_ranges = request.get_header_ranges(&["Host"]).unwrap();
        assert_eq!(header_ranges.len(), 1);
        assert_eq!(header_ranges[0], 25..43);
        assert_eq!(&input[header_ranges[0].clone()], "Host: example.com\n");

        // Test body keypath extraction with exact ranges and values
        let body_ranges = request.get_body_keypaths_ranges(&["name", "age"]).unwrap();
        assert_eq!(body_ranges.len(), 2);
        assert_eq!(body_ranges[0], 76..90);
        assert_eq!(&input[body_ranges[0].clone()], "\"name\":\"Alice\"");
        assert_eq!(body_ranges[1], 91..99);
        assert_eq!(&input[body_ranges[1].clone()], "\"age\":30");
    }

    #[test]
    fn test_response_parsing_and_range_extraction() {
        shared::init_test_logging();

        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

1a
{"status":"success"}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();

        // Test status line with exact range and value
        let status_line_range = response.get_status_line_range();
        assert_eq!(status_line_range, 0..16);
        assert_eq!(&input[status_line_range], "HTTP/1.1 200 OK\n");

        // Test header extraction with exact ranges and values
        let header_ranges = response.get_header_ranges(&["Content-Type"]).unwrap();
        assert_eq!(header_ranges.len(), 1);
        assert_eq!(header_ranges[0], 16..47);
        assert_eq!(
            &input[header_ranges[0].clone()],
            "Content-Type: application/json\n"
        );

        // Test body keypath extraction with exact ranges and values
        let body_ranges = response.get_body_keypaths_ranges(&["status"]).unwrap();
        assert_eq!(body_ranges.len(), 1);
        assert_eq!(body_ranges[0], 52..70);
        assert_eq!(&input[body_ranges[0].clone()], "\"status\":\"success\"");
    }

    #[test]
    fn test_nested_json_keypath_ranges() {
        shared::init_test_logging();

        let input = r#"POST /api/test HTTP/1.1
Host: api.example.com

{"user":{"profile":{"name":"Bob","age":25}}}"#;

        let request = RequestParser::parse_request(input).unwrap();

        // Test request line with exact range
        let request_line_range = request.get_request_line_range();
        assert_eq!(request_line_range, 0..24);
        assert_eq!(&input[request_line_range], "POST /api/test HTTP/1.1\n");

        // Test nested keypaths with exact ranges and values
        let ranges = request
            .get_body_keypaths_ranges(&["user.profile.name", "user.profile.age"])
            .unwrap();

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 67..79);
        assert_eq!(&input[ranges[0].clone()], "\"name\":\"Bob\"");
        assert_eq!(ranges[1], 80..88);
        assert_eq!(&input[ranges[1].clone()], "\"age\":25");
    }

    #[test]
    fn test_multiple_headers_range_extraction() {
        shared::init_test_logging();

        let input = r#"GET /api/data HTTP/1.1
Host: example.com
User-Agent: TestClient/1.0
Authorization: Bearer token123

"#;

        let request = RequestParser::parse_request(input).unwrap();

        // Test request line with exact range
        let request_line_range = request.get_request_line_range();
        assert_eq!(request_line_range, 0..23);
        assert_eq!(&input[request_line_range], "GET /api/data HTTP/1.1\n");

        // Test multiple headers with exact ranges and values
        let ranges = request
            .get_header_ranges(&["Host", "User-Agent", "Authorization"])
            .unwrap();

        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], 23..41);
        assert_eq!(&input[ranges[0].clone()], "Host: example.com\n");
        assert_eq!(ranges[1], 41..68);
        assert_eq!(&input[ranges[1].clone()], "User-Agent: TestClient/1.0\n");
        assert_eq!(ranges[2], 68..99);
        assert_eq!(
            &input[ranges[2].clone()],
            "Authorization: Bearer token123\n"
        );
    }

    #[test]
    fn test_response_with_nested_json() {
        shared::init_test_logging();

        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

3a
{"data":{"users":[{"id":1},{"id":2}]}}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();

        // Test status line with exact range
        let status_line_range = response.get_status_line_range();
        assert_eq!(status_line_range, 0..16);
        assert_eq!(&input[status_line_range], "HTTP/1.1 200 OK\n");

        // Test nested keypath with exact range and value
        let ranges = response.get_body_keypaths_ranges(&["data.users"]).unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 60..87);
        assert_eq!(
            &input[ranges[0].clone()],
            "\"users\":[{\"id\":1},{\"id\":2}]"
        );
    }

    #[test]
    fn test_request_without_body() {
        shared::init_test_logging();

        let input = "GET /api/test HTTP/1.1\nHost: example.com\n\n";

        let request = RequestParser::parse_request(input).unwrap();

        // Test request line with exact range and value
        let request_line_range = request.get_request_line_range();
        assert_eq!(request_line_range, 0..23);
        assert_eq!(&input[request_line_range], "GET /api/test HTTP/1.1\n");

        // Test header with exact range and value
        let header_ranges = request.get_header_ranges(&["Host"]).unwrap();
        assert_eq!(header_ranges.len(), 1);
        assert_eq!(header_ranges[0], 23..41);
        assert_eq!(&input[header_ranges[0].clone()], "Host: example.com\n");

        // Verify body is None
        assert!(request.body.is_none());

        // Requesting keypaths on a request without body should return error
        let result = request.get_body_keypaths_ranges(&["any.path"]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParserError::MissingField("request body")
        ));
    }

    #[test]
    fn test_non_existent_keypaths() {
        shared::init_test_logging();

        let input = r#"POST /test HTTP/1.1
Host: example.com

{"name":"Alice"}"#;

        let request = RequestParser::parse_request(input).unwrap();

        // Should return error for non-existent keypath
        let result = request.get_body_keypaths_ranges(&["nonexistent"]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParserError::KeypathNotFound(_)
        ));

        // Should return error for header that doesn't exist
        let header_result = request.get_header_ranges(&["NonExistent"]);
        assert!(header_result.is_err());
        assert!(matches!(
            header_result.unwrap_err(),
            ParserError::HeaderNotFound(_)
        ));
    }

    #[test]
    fn test_array_indexing_in_http_response() {
        shared::init_test_logging();

        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

26
{"users":[{"id":1},{"id":2}]}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();

        // Test status line
        let status_line_range = response.get_status_line_range();
        assert_eq!(&input[status_line_range], "HTTP/1.1 200 OK\n");

        // Test accessing array field
        let ranges = response.get_body_keypaths_ranges(&["users"]).unwrap();
        assert_eq!(ranges.len(), 1);
        assert!(&input[ranges[0].clone()].contains("[{\"id\":1},{\"id\":2}]"));

        // Test accessing array elements by index
        let ranges = response
            .get_body_keypaths_ranges(&["users[0]", "users[1]"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
        assert!(&input[ranges[0].clone()].contains("\"id\":1"));
        assert!(&input[ranges[1].clone()].contains("\"id\":2"));

        // Test accessing nested fields in array elements
        let ranges = response
            .get_body_keypaths_ranges(&["users[0].id", "users[1].id"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
        assert!(&input[ranges[0].clone()].contains("\"id\":1"));
        assert!(&input[ranges[1].clone()].contains("\"id\":2"));
    }

    #[test]
    fn test_range_boundaries_are_valid() {
        shared::init_test_logging();

        let input = r#"POST /api HTTP/1.1
Host: test.com

{"x":1}"#;

        let request = RequestParser::parse_request(input).unwrap();

        // Test request line with exact range and value
        let request_line_range = request.get_request_line_range();
        assert_eq!(request_line_range, 0..19);
        assert_eq!(&input[request_line_range.clone()], "POST /api HTTP/1.1\n");
        assert!(request_line_range.start < request_line_range.end);
        assert!(request_line_range.end <= input.len());

        // Test header with exact range and value
        let header_ranges = request.get_header_ranges(&["Host"]).unwrap();
        assert_eq!(header_ranges.len(), 1);
        assert_eq!(header_ranges[0], 19..34);
        assert_eq!(&input[header_ranges[0].clone()], "Host: test.com\n");
        for range in &header_ranges {
            assert!(range.start < range.end);
            assert!(range.end <= input.len());
        }

        // Test body keypath with exact range and value
        let body_ranges = request.get_body_keypaths_ranges(&["x"]).unwrap();
        assert_eq!(body_ranges.len(), 1);
        assert_eq!(body_ranges[0], 36..41);
        assert_eq!(&input[body_ranges[0].clone()], "\"x\":1");
        for range in &body_ranges {
            assert!(range.start < range.end);
            assert!(range.end <= input.len());
        }
    }

    #[test]
    fn test_complete_workflow() {
        shared::init_test_logging();

        let request_str = r#"POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"user":{"name":"Charlie","email":"charlie@example.com","age":28}}"#;

        let request = RequestParser::parse_request(request_str).unwrap();

        // Test request line with exact range and value
        let request_line_range = request.get_request_line_range();
        assert_eq!(request_line_range, 0..25);
        assert_eq!(
            &request_str[request_line_range],
            "POST /api/users HTTP/1.1\n"
        );

        // Test headers with exact ranges and values
        let headers = request
            .get_header_ranges(&["Host", "Content-Type"])
            .unwrap();
        assert_eq!(headers.len(), 2);

        assert_eq!(headers[0], 25..47);
        assert_eq!(&request_str[headers[0].clone()], "Host: api.example.com\n");

        assert_eq!(headers[1], 47..78);
        assert_eq!(
            &request_str[headers[1].clone()],
            "Content-Type: application/json\n"
        );

        // Test body keypaths with exact ranges and values
        let body_parts = request
            .get_body_keypaths_ranges(&["user.name", "user.email", "user.age"])
            .unwrap();
        assert_eq!(body_parts.len(), 3);

        assert_eq!(body_parts[0], 88..104);
        assert_eq!(&request_str[body_parts[0].clone()], "\"name\":\"Charlie\"");

        assert_eq!(body_parts[1], 105..134);
        assert_eq!(
            &request_str[body_parts[1].clone()],
            "\"email\":\"charlie@example.com\""
        );

        assert_eq!(body_parts[2], 135..143);
        assert_eq!(&request_str[body_parts[2].clone()], "\"age\":28");
    }
}
