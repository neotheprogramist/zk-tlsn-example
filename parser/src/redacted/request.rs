use std::{collections::HashMap, ops::Range, str::FromStr};

use pest::Parser;
use pest_derive::Parser;

use super::traversal::{BodyConfig, HeaderConfig};
use crate::{
    HttpMessageBuilder,
    common::{assert_end_of_iterator, assert_rule},
    error::{ParseError, Result},
    traits::{RangeExtractor, Traverser},
    types::{Body, Header},
};

#[derive(Parser)]
#[grammar = "./redacted/request.pest"]
pub struct RequestParser;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Range<usize>,
    pub url: Range<usize>,
    pub protocol_version: Range<usize>,
    pub headers: HashMap<String, Vec<Header>>,
    pub chunk_size: Range<usize>,
    pub body: HashMap<String, Body>,
}

pub struct RequestBuilder {
    header_config: HeaderConfig<Rule>,
    body_config: BodyConfig<Rule>,
}

impl RequestBuilder {
    pub fn new() -> Self {
        Self {
            header_config: HeaderConfig::new(
                Rule::headers,
                Rule::header,
                Rule::header_name,
                Rule::header_value,
            ),
            body_config: BodyConfig::new(Rule::pair),
        }
    }

    pub fn parse(&self, input: &str) -> Result<Request> {
        let pairs = RequestParser::parse(Rule::request, input)
            .map_err(|e| ParseError::InvalidSyntax(format!("Failed to parse HTTP request: {e}")))?;

        HttpMessageBuilder::parse(self, pairs)
    }
}

impl HttpMessageBuilder for RequestBuilder {
    type Rule = Rule;
    type Message = Request;

    fn build_message(
        &self,
        first_line: (Range<usize>, Range<usize>, Range<usize>),
        headers: HashMap<String, Vec<Header>>,
        chunk_size: Range<usize>,
        body: HashMap<String, Body>,
    ) -> Self::Message {
        Request {
            method: first_line.0,
            url: first_line.1,
            protocol_version: first_line.2,
            headers,
            chunk_size,
            body,
        }
    }

    fn parse_first_line(
        &self,
        request_line: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>)> {
        assert_rule(&request_line, Rule::request_line, "request_line")?;

        let mut inner = request_line.into_inner();
        let method = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("method".to_string()))?;
        let url = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("url".to_string()))?;
        let protocol_version = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("protocol version".to_string()))?;

        assert_rule(&method, Rule::method, "method")?;
        assert_rule(&url, Rule::url, "url")?;
        assert_rule(
            &protocol_version,
            Rule::protocol_version,
            "protocol_version",
        )?;

        assert_end_of_iterator(&mut inner, "request_line")?;

        Ok((
            method.extract_range(),
            url.extract_range(),
            protocol_version.extract_range(),
        ))
    }

    // Override parse to handle redacted structure where pairs come directly after chunk_size
    fn parse(&self, mut pairs: pest::iterators::Pairs<'_, Self::Rule>) -> Result<Self::Message> {
        use super::traversal::{BodyTraverser, HeaderTraverser};

        let first_line_pair = pairs
            .next()
            .ok_or_else(|| ParseError::MissingField("first line".to_string()))?;
        let headers_pair = pairs
            .next()
            .ok_or_else(|| ParseError::MissingField("headers section".to_string()))?;
        let chunk_size_pair = pairs
            .next()
            .ok_or_else(|| ParseError::MissingField("chunk size".to_string()))?;

        assert_rule(&chunk_size_pair, Rule::chunk_size, "chunk_size")?;

        let first_line = self.parse_first_line(first_line_pair)?;
        let headers = HeaderTraverser::new(self.header_config, headers_pair)?.traverse()?;
        let chunk_size = chunk_size_pair.extract_range();

        let body_traverser = BodyTraverser::new(self.body_config);
        let body = body_traverser.traverse(pairs)?;

        Ok(self.build_message(first_line, headers, chunk_size, body))
    }
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for Request {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        RequestBuilder::new().parse(s)
    }
}
