//! HTTP Request/Response Parser with Range Tracking
//!
//! This crate provides parsers for HTTP requests and responses that track
//! the byte ranges of all parsed elements in the original input. This is
//! useful for applications that need to reference specific parts of the
//! HTTP message, such as selective disclosure in TLS proofs.
//!
//! # Examples
//!
//! ```no_run
//! use parser::{RequestParser, ResponseParser};
//!
//! // Parse an HTTP request
//! let request_str = "GET /api/users HTTP/1.1\nHost: example.com\n\n";
//! let request = RequestParser::parse_request(request_str).unwrap();
//!
//! // Parse an HTTP response
//! let response_str = r#"HTTP/1.1 200 OK
//! Content-Type: application/json
//!
//! 1a
//! {"status": "success"}
//! 0
//! "#;
//! let response = ResponseParser::parse_response(response_str).unwrap();
//! ```

mod error;
mod grammar;
mod search;
mod types;

// Re-export public API
pub use error::ParserError;
pub use grammar::{RequestParser, ResponseParser};
pub use search::{BodySearchable, HeaderSearchable};
pub use types::{RangedHeader, RangedValue, Request, Response};
