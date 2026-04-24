use std::{collections::HashMap, ops::Range, str::FromStr};

use pest::Parser;
use pest_derive::Parser;

use super::{
    Body, Header,
    traversal::{BodyConfig, HeaderConfig},
};
use crate::parser::{
    HttpMessageBuilder,
    error::{ParseError, Result},
    parse_three_field_line,
    traits::{HttpMessage, Traverser},
};

#[derive(Parser)]
#[grammar = "./parser/standard/request.pest"]
pub struct RequestParser;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Range<usize>,
    pub url: Range<usize>,
    pub protocol_version: Range<usize>,
    pub headers: HashMap<String, Vec<Header>>,
    pub body: HashMap<String, Body>,
}

impl HttpMessage for Request {
    type Header = Header;
    type Body = Body;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>> {
        &self.headers
    }

    fn body(&self) -> &HashMap<String, Self::Body> {
        &self.body
    }
}

pub struct RequestBuilder {
    header_config: HeaderConfig<Rule>,
    body_config: BodyConfig<Rule>,
}

impl RequestBuilder {
    #[must_use]
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
        let pairs = RequestParser::parse(Rule::request, input)?;
        HttpMessageBuilder::parse(self, pairs)
    }
}

impl HttpMessageBuilder for RequestBuilder {
    type Rule = Rule;
    type Message = Request;
    type Header = Header;
    type Body = Body;

    fn build_message(
        &self,
        first_line: (Range<usize>, Range<usize>, Range<usize>),
        headers: HashMap<String, Vec<Header>>,
        body: HashMap<String, Body>,
    ) -> Self::Message {
        Request {
            method: first_line.0,
            url: first_line.1,
            protocol_version: first_line.2,
            headers,
            body,
        }
    }

    fn parse_first_line(
        &self,
        request_line: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>)> {
        parse_three_field_line(
            request_line,
            Rule::request_line,
            "request_line",
            [
                (Rule::method, "method"),
                (Rule::url, "url"),
                (Rule::protocol_version, "protocol_version"),
            ],
        )
    }

    fn parse(&self, mut pairs: pest::iterators::Pairs<'_, Self::Rule>) -> Result<Self::Message> {
        use super::traversal::{BodyTraverser, HeaderTraverser};

        let first_line_pair = pairs
            .next()
            .ok_or_else(|| ParseError::MissingField("first line".to_string()))?;
        let headers_pair = pairs
            .next()
            .ok_or_else(|| ParseError::MissingField("headers section".to_string()))?;

        let first_line = self.parse_first_line(first_line_pair)?;
        let headers = HeaderTraverser::new(self.header_config, headers_pair)?.traverse()?;

        let body = if let Some(body_pair) = pairs.next()
            && (body_pair.as_rule() == Rule::object || body_pair.as_rule() == Rule::array)
        {
            BodyTraverser::new(self.body_config, body_pair)?.traverse()?
        } else {
            HashMap::new()
        };

        Ok(self.build_message(first_line, headers, body))
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
