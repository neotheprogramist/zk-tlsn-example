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

mod common;
mod error;
mod ranged;
pub mod redacted;
mod search;
pub mod standard;

// Re-export public API
pub use error::ParserError;
pub use ranged::{RangedText, RangedValue};
pub use redacted::{
    ParsedRedactedRequest, ParsedRedactedResponse, RedactedRequestParser, RedactedResponseParser,
};
pub use search::{BodySearchable, HeaderSearchable};
pub use standard::{ParsedRequest, ParsedResponse, RequestParser, ResponseParser};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end_request_flow() {
        shared::init_test_logging();

        let input = r#"POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"user":{"name":"Charlie","email":"charlie@example.com","age":28}}"#;

        let request = RequestParser::parse_request(input).unwrap();

        let request_line_range = request.get_request_line_range();
        assert_eq!(&input[request_line_range], "POST /api/users HTTP/1.1\n");

        let header_ranges = request
            .get_header_ranges(&["Host", "Content-Type"])
            .unwrap();
        assert_eq!(header_ranges.len(), 2);
        assert_eq!(&input[header_ranges[0].clone()], "Host: api.example.com\n");
        assert_eq!(
            &input[header_ranges[1].clone()],
            "Content-Type: application/json\n"
        );

        let body_ranges = request
            .get_body_keypaths_ranges(&["user.name", "user.email", "user.age"])
            .unwrap();
        assert_eq!(body_ranges.len(), 3);
        assert_eq!(&input[body_ranges[0].clone()], "\"name\":\"Charlie\"");
        assert_eq!(
            &input[body_ranges[1].clone()],
            "\"email\":\"charlie@example.com\""
        );
        assert_eq!(&input[body_ranges[2].clone()], "\"age\":28");
    }

    #[test]
    fn test_end_to_end_response_flow() {
        shared::init_test_logging();

        let input = r#"HTTP/1.1 200 OK
Content-Type: application/json

3a
{"data":{"users":[{"id":1},{"id":2}]}}
0
"#;

        let response = ResponseParser::parse_response(input).unwrap();

        let status_line_range = response.get_status_line_range();
        assert_eq!(&input[status_line_range], "HTTP/1.1 200 OK\n");

        let header_ranges = response.get_header_ranges(&["Content-Type"]).unwrap();
        assert_eq!(header_ranges.len(), 1);
        assert_eq!(
            &input[header_ranges[0].clone()],
            "Content-Type: application/json\n"
        );

        let body_ranges = response
            .get_body_keypaths_ranges(&["data.users", "data.users[0].id", "data.users[1].id"])
            .unwrap();
        assert_eq!(body_ranges.len(), 3);
        assert_eq!(
            &input[body_ranges[0].clone()],
            "\"users\":[{\"id\":1},{\"id\":2}]"
        );
        assert_eq!(&input[body_ranges[1].clone()], "\"id\":1");
        assert_eq!(&input[body_ranges[2].clone()], "\"id\":2");
    }
}
