use std::{collections::HashMap, ops::Range};

use crate::parser::traits::HttpMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<V> {
    pub name: Range<usize>,
    pub value: V,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body<V> {
    KeyValue { key: Range<usize>, value: V },
    Value(Range<usize>),
}

#[derive(Debug, Clone)]
pub struct Request<H, B> {
    pub method: Range<usize>,
    pub url: Range<usize>,
    pub protocol_version: Range<usize>,
    pub headers: HashMap<String, Vec<H>>,
    pub body: HashMap<String, B>,
}

#[derive(Debug, Clone)]
pub struct Response<H, B> {
    pub protocol_version: Range<usize>,
    pub status_code: Range<usize>,
    pub status: Range<usize>,
    pub headers: HashMap<String, Vec<H>>,
    pub body: HashMap<String, B>,
}

impl<H, B> HttpMessage for Request<H, B> {
    type Header = H;
    type Body = B;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>> {
        &self.headers
    }

    fn body(&self) -> &HashMap<String, Self::Body> {
        &self.body
    }
}

impl<H, B> HttpMessage for Response<H, B> {
    type Header = H;
    type Body = B;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>> {
        &self.headers
    }

    fn body(&self) -> &HashMap<String, Self::Body> {
        &self.body
    }
}
