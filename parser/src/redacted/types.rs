use std::collections::HashMap;

use crate::ranged::{RangedText, RangedValue};

#[derive(Debug)]
pub struct Request {
    pub request_line: RangedText,
    pub headers: HashMap<String, RangedText>,
    pub body: HashMap<String, RangedValue>,
}

impl Request {
    pub fn new(
        request_line: RangedText,
        headers: HashMap<String, RangedText>,
        body: HashMap<String, RangedValue>,
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
    pub body: HashMap<String, RangedValue>,
}

impl Response {
    pub fn new(
        status_line: RangedText,
        headers: HashMap<String, RangedText>,
        body: HashMap<String, RangedValue>,
    ) -> Self {
        Self {
            status_line,
            headers,
            body,
        }
    }
}
