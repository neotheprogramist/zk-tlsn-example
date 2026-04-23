mod request;
mod response;
mod traversal;

use std::ops::Range;

pub use request::Request;
pub use response::Response;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Range<usize>,
    pub value: Option<Range<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    KeyValue {
        key: Range<usize>,
        value: Option<Range<usize>>,
    },
    Value(Range<usize>),
}
