//! # Parser
//!
//! A zero-copy HTTP parser that extracts byte ranges from the original input.
//!
//! This library parses HTTP requests and responses with chunked transfer encoding and JSON bodies,
//! storing only byte ranges rather than copying data. This enables efficient parsing
//! and selective extraction of components.
//!
//! ## Features
//!
//! - **Zero-copy parsing**: Stores `Range<usize>` instead of copying strings
//! - **Chunked transfer encoding**: Supports HTTP chunked messages
//! - **Nested JSON traversal**: Parses and indexes nested JSON structures
//! - **Type-safe parsing**: Uses Rust's type system and the pest parser
//! - **Case-insensitive headers**: HTTP header lookups are case-insensitive
//! - **Multiple header support**: Handles duplicate headers (e.g., Set-Cookie)

mod common;
mod error;
mod message;
mod path;
mod traits;
mod traversal;
mod types;

pub mod standard;

pub use common::HttpMessageBuilder;
pub use error::{ParseError, Result};
pub use message::HttpMessage;
pub use standard::{Request, Response};
pub use types::{Body, Header};

pub mod prelude {
    pub use crate::{
        HttpMessage, Request, Response,
        error::{ParseError, Result},
        types::{Body, Header},
    };
}
