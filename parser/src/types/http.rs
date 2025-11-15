use std::collections::HashMap;

use super::ranged::{RangedHeader, RangedValue};

#[derive(Debug)]
pub struct Request {
    pub request_line: RangedHeader,
    pub headers: HashMap<String, RangedHeader>,
    pub body: Option<RangedValue>,
}

impl Request {
    pub fn new(
        request_line: RangedHeader,
        headers: HashMap<String, RangedHeader>,
        body: Option<RangedValue>,
    ) -> Self {
        Self {
            request_line,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub headers: HashMap<String, RangedHeader>,
    pub body: RangedValue,
}

impl Response {
    pub fn new(headers: HashMap<String, RangedHeader>, body: RangedValue) -> Self {
        Self { headers, body }
    }
}
