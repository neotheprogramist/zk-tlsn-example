use std::ops::Range;

pub trait JsonFieldRangeExt {
    fn with_quotes_and_colon(&self) -> Range<usize>;
    fn with_quotes(&self) -> Range<usize>;
    fn without_quotes(&self) -> Range<usize>;
    fn with_opening_quote(&self) -> Range<usize>;
    fn full_pair_quoted(&self, value_range: &Range<usize>) -> Range<usize>;
    fn full_pair_unquoted(&self, value_range: &Range<usize>) -> Range<usize>;
    fn with_newline(&self) -> Range<usize>;
    fn with_crlf(&self) -> Range<usize>;
    fn with_separator(&self) -> Range<usize>;
    fn header_full_range(&self, value_range: &Range<usize>) -> Range<usize>;
}

impl JsonFieldRangeExt for Range<usize> {
    fn with_quotes_and_colon(&self) -> Range<usize> {
        self.start.saturating_sub(1)..(self.end + 2)
    }

    fn with_quotes(&self) -> Range<usize> {
        self.start.saturating_sub(1)..(self.end + 1)
    }

    fn without_quotes(&self) -> Range<usize> {
        self.clone()
    }

    fn with_opening_quote(&self) -> Range<usize> {
        self.start.saturating_sub(1)..self.end
    }

    fn full_pair_quoted(&self, value_range: &Range<usize>) -> Range<usize> {
        self.start.saturating_sub(1)..(value_range.end + 1)
    }

    fn full_pair_unquoted(&self, value_range: &Range<usize>) -> Range<usize> {
        self.start.saturating_sub(1)..value_range.end
    }

    fn with_newline(&self) -> Range<usize> {
        self.start..self.end + 1
    }

    fn with_crlf(&self) -> Range<usize> {
        self.start..self.end + 2
    }

    fn with_separator(&self) -> Range<usize> {
        self.start..self.end + 2
    }

    fn header_full_range(&self, value_range: &Range<usize>) -> Range<usize> {
        self.start..value_range.end + 1
    }
}
