use std::ops::Range;

pub trait JsonFieldRangeExt {
    fn adjust(&self, start_off: isize, end_off: isize) -> Range<usize>;
    fn extend_to(&self, end: usize) -> Range<usize>;
    fn with_quotes_and_colon(&self) -> Range<usize> {
        self.adjust(-1, 2)
    }
    fn with_quotes(&self) -> Range<usize> {
        self.adjust(-1, 1)
    }
    fn without_quotes(&self) -> Range<usize>;
    fn with_opening_quote(&self) -> Range<usize> {
        self.adjust(-1, 0)
    }
    fn full_pair_quoted(&self, value: &Range<usize>) -> Range<usize> {
        self.extend_to(value.end + 1)
    }
    fn full_pair_unquoted(&self, value: &Range<usize>) -> Range<usize> {
        self.extend_to(value.end)
    }
    fn with_newline(&self) -> Range<usize> {
        self.adjust(0, 1)
    }
    fn with_crlf(&self) -> Range<usize> {
        self.adjust(0, 2)
    }
    fn with_separator(&self) -> Range<usize> {
        self.adjust(0, 2)
    }
    fn header_full_range(&self, value: &Range<usize>) -> Range<usize> {
        self.extend_to(value.end + 1)
    }
}

impl JsonFieldRangeExt for Range<usize> {
    fn adjust(&self, start_off: isize, end_off: isize) -> Range<usize> {
        (self.start as isize + start_off).max(0) as usize..(self.end as isize + end_off) as usize
    }
    fn extend_to(&self, end: usize) -> Range<usize> {
        self.start.saturating_sub(1)..end
    }
    fn without_quotes(&self) -> Range<usize> {
        self.clone()
    }
}
