use std::ops::Range;

use crate::traits::{HttpBody, HttpHeader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Range<usize>,
    pub value: Option<Range<usize>>,
}

impl Header {
    pub fn value_with_newline(&self) -> Option<Range<usize>> {
        self.value.as_ref().map(|v| v.start..v.end + 1)
    }
}

impl HttpHeader for Header {
    fn full_range(&self) -> Range<usize> {
        match &self.value {
            Some(value) => self.name.start..value.end + 1,
            None => self.name.start..self.name.end + 3, // name + ": " + newline
        }
    }

    fn name_with_separator(&self) -> Range<usize> {
        self.name.start..self.name.end + 2
    }

    fn name_range(&self) -> &Range<usize> {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    KeyValue {
        key: Range<usize>,
        value: Option<Range<usize>>,
    },
    Value(Range<usize>),
}

impl Body {
    pub fn value_with_quotes(&self) -> Option<Range<usize>> {
        match self {
            Body::KeyValue { value, .. } => value.as_ref().map(|v| v.start - 1..v.end + 1),
            Body::Value(range) => Some(range.start - 1..range.end + 1),
        }
    }
}

impl HttpBody for Body {
    fn key_with_quotes_and_colon(&self) -> Option<Range<usize>> {
        match self {
            Body::KeyValue { key, .. } => Some(key.start - 1..key.end + 2),
            Body::Value(_) => None,
        }
    }

    fn full_pair_range(&self) -> Range<usize> {
        match self {
            Body::KeyValue { key, value } => match value {
                Some(v) => key.start - 1..v.end + 1,
                None => key.start - 1..key.end + 2, // key with quotes and colon
            },
            Body::Value(range) => range.clone(),
        }
    }
}
