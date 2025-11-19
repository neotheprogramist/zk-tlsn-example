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

impl HttpMessage for Response {
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
