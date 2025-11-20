use std::{collections::HashMap, ops::Range, str::FromStr};

use pest::Parser;
use pest_derive::Parser;

use super::traversal::{BodyConfig, HeaderConfig};
use crate::{
    HttpMessageBuilder,
    common::{assert_end_of_iterator, assert_rule},
    error::{ParseError, Result},
    traits::RangeExtractor,
    types::{Body, Header},
};

#[derive(Parser)]
#[grammar = "./standard/response.pest"]
pub struct ResponseParser;

#[derive(Debug, Clone)]
pub struct Response {
    pub protocol_version: Range<usize>,
    pub status_code: Range<usize>,
    pub status: Range<usize>,
    pub headers: HashMap<String, Vec<Header>>,
    pub chunk_size: Range<usize>,
    pub body: HashMap<String, Body>,
}

pub struct ResponseBuilder {
    header_config: HeaderConfig<Rule>,
    body_config: BodyConfig<Rule>,
}

impl ResponseBuilder {
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

    pub fn parse(&self, input: &str) -> Result<Response> {
        let pairs = ResponseParser::parse(Rule::response, input).map_err(|e| {
            ParseError::InvalidSyntax(format!("Failed to parse HTTP response: {e}"))
        })?;

        HttpMessageBuilder::parse(self, pairs)
    }
}

impl HttpMessageBuilder for ResponseBuilder {
    type Rule = Rule;
    type Message = Response;

    fn build_message(
        &self,
        first_line: (Range<usize>, Range<usize>, Range<usize>),
        headers: HashMap<String, Vec<Header>>,
        chunk_size: Range<usize>,
        body: HashMap<String, Body>,
    ) -> Self::Message {
        Response {
            protocol_version: first_line.0,
            status_code: first_line.1,
            status: first_line.2,
            headers,
            chunk_size,
            body,
        }
    }

    fn parse_first_line(
        &self,
        status_line: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>)> {
        assert_rule(&status_line, Rule::status_line, "status_line")?;

        let mut inner = status_line.into_inner();
        let protocol_version = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("protocol version".to_string()))?;
        let status_code = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("status code".to_string()))?;
        let status = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("status".to_string()))?;

        assert_rule(
            &protocol_version,
            Rule::protocol_version,
            "protocol_version",
        )?;
        assert_rule(&status_code, Rule::status_code, "status_code")?;
        assert_rule(&status, Rule::status, "status")?;

        assert_end_of_iterator(&mut inner, "status_line")?;

        Ok((
            protocol_version.extract_range(),
            status_code.extract_range(),
            status.extract_range(),
        ))
    }

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
        let body_pair = pairs
            .next()
            .ok_or_else(|| ParseError::MissingField("body".to_string()))?;

        assert_rule(&chunk_size_pair, Rule::chunk_size, "chunk_size")?;

        let first_line = self.parse_first_line(first_line_pair)?;
        let headers = HeaderTraverser::new(self.header_config, headers_pair)?.traverse()?;
        let chunk_size = chunk_size_pair.extract_range();
        let body = BodyTraverser::new(self.body_config, body_pair)?.traverse()?;

        Ok(self.build_message(first_line, headers, chunk_size, body))
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for Response {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        ResponseBuilder::new().parse(s)
    }
}
