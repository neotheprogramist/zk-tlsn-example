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

pub trait HttpHeader {
    fn full_range(&self) -> Range<usize>;

    fn name_with_separator(&self) -> Range<usize>;

    fn name_range(&self) -> &Range<usize>;
}

pub trait HttpBody {
    fn key_with_quotes_and_colon(&self) -> Option<Range<usize>>;

    fn full_pair_range(&self) -> Range<usize>;
}

pub trait HttpMessage {
    type Header: HttpHeader;
    type Body: HttpBody;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>>;

    fn body(&self) -> &HashMap<String, Self::Body>;
}
