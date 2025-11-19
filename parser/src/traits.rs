use std::ops::Range;

use pest::{RuleType, iterators::Pair};

pub trait RangeExtractor {
    fn extract_range(&self) -> Range<usize>;
}

impl<R: RuleType> RangeExtractor for Pair<'_, R> {
    fn extract_range(&self) -> Range<usize> {
        self.as_span().start()..self.as_span().end()
    }
}
