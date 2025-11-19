use std::{collections::HashMap, ops::Range, str::FromStr};

use pest::Parser;
use pest_derive::Parser;

use crate::{
    HttpMessage, HttpMessageBuilder,
    error::{ParseError, Result},
    traits::RangeExtractor,
    traversal::{BodyConfig, HeaderConfig, assert_end_of_iterator, assert_rule},
    types::{Body, Header},
};

#[derive(Parser)]
#[grammar = "./standard/request.pest"]
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
            body_config: BodyConfig::new(Rule::object, Rule::pair, Rule::array),
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

    fn header_config(&self) -> HeaderConfig<Self::Rule> {
        self.header_config
    }

    fn body_config(&self) -> BodyConfig<Self::Rule> {
        self.body_config
    }

    fn chunk_size_rule(&self) -> Self::Rule {
        Rule::chunk_size
    }

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

impl HttpMessage for Request {
    fn headers(&self) -> &HashMap<String, Vec<Header>> {
        &self.headers
    }

    fn chunk_size(&self) -> &Range<usize> {
        &self.chunk_size
    }

    fn body(&self) -> &HashMap<String, Body> {
        &self.body
    }
}
