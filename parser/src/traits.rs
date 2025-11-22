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

pub trait HttpMessage {
    type Header;
    type Body;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>>;

    fn body(&self) -> &HashMap<String, Self::Body>;
}
