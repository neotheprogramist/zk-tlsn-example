use std::collections::HashMap;

use super::ranged::{RangedText, RangedValue};

#[derive(Debug)]
pub struct Request {
    pub request_line: RangedText,
    pub headers: HashMap<String, RangedText>,
    pub body: Option<RangedValue>,
}

impl Request {
    pub fn new(
        request_line: RangedText,
        headers: HashMap<String, RangedText>,
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
    pub status_line: RangedText,
    pub headers: HashMap<String, RangedText>,
    pub body: RangedValue,
}

impl Response {
    pub fn new(
        status_line: RangedText,
        headers: HashMap<String, RangedText>,
        body: RangedValue,
    ) -> Self {
        Self {
            status_line,
            headers,
            body,
        }
    }
}
