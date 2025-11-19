use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Range<usize>,
    pub value: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    KeyValue {
        key: Range<usize>,
        value: Range<usize>,
    },
    Value(Range<usize>),
}
