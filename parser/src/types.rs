use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Range<usize>,
    pub value: Range<usize>,
}

impl Header {
    pub fn full_range(&self) -> Range<usize> {
        self.name.start..self.value.end + 1
    }

    pub fn name_with_separator(&self) -> Range<usize> {
        self.name.start..self.name.end + 2
    }

    pub fn value_with_newline(&self) -> Range<usize> {
        self.value.start..self.value.end + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    KeyValue {
        key: Range<usize>,
        value: Range<usize>,
    },
    Value(Range<usize>),
}

impl Body {
    pub fn key_with_quotes_and_colon(&self) -> Option<Range<usize>> {
        match self {
            Body::KeyValue { key, .. } => Some(key.start - 1..key.end + 2),
            Body::Value(_) => None,
        }
    }

    pub fn value_with_quotes(&self) -> Range<usize> {
        match self {
            Body::KeyValue { value, .. } => value.start - 1..value.end + 1,
            Body::Value(range) => range.start - 1..range.end + 1,
        }
    }

    pub fn full_pair_range(&self) -> Range<usize> {
        match self {
            Body::KeyValue { key, value } => key.start - 1..value.end + 1,
            Body::Value(range) => range.clone(),
        }
    }
}
