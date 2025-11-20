use std::{collections::HashMap, ops::Range};

use pest::{RuleType, iterators::Pair};

use crate::error::Result;

pub trait RangeExtractor {
    fn extract_range(&self) -> Range<usize>;
}

impl<R: RuleType> RangeExtractor for Pair<'_, R> {
    fn extract_range(&self) -> Range<usize> {
        self.as_span().start()..self.as_span().end()
    }
}

pub trait Traverser {
    type Output;

    fn traverse(self) -> Result<HashMap<String, Self::Output>>;
}

/// Trait for HTTP header operations
pub trait HttpHeader {
    /// Returns the full range of the header including name, separator, value, and newline
    fn full_range(&self) -> Range<usize>;

    /// Returns the range of the header name with the colon and space separator (": ")
    fn name_with_separator(&self) -> Range<usize>;

    /// Returns the name range
    fn name_range(&self) -> &Range<usize>;
}

/// Trait for HTTP body operations
pub trait HttpBody {
    /// Returns the key with surrounding quotes and colon for `KeyValue` variants
    fn key_with_quotes_and_colon(&self) -> Option<Range<usize>>;

    /// Returns the full range of a key-value pair or value
    fn full_pair_range(&self) -> Range<usize>;
}

/// Trait for HTTP messages (Request/Response)
pub trait HttpMessage {
    type Header: HttpHeader;
    type Body: HttpBody;

    /// Returns the headers map
    fn headers(&self) -> &HashMap<String, Vec<Self::Header>>;

    /// Returns the body map
    fn body(&self) -> &HashMap<String, Self::Body>;

    /// Returns the chunk size range
    fn chunk_size(&self) -> &Range<usize>;

    /// Returns the chunk size with newline
    fn chunk_size_with_newline(&self) -> Range<usize> {
        self.chunk_size().start..self.chunk_size().end + 1
    }
}
