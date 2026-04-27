use std::{collections::HashMap, ops::Range, str::FromStr};

use pest::{Parser as _, iterators::Pairs};

use crate::parser::{
    common::{parse_http_message, parse_three_field_line},
    error::{ParseError, Result},
    http,
    traversal::{HeaderValue, parse_headers, parse_redacted_body, parse_standard_body},
};

mod grammar {
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "./parser/grammar.pest"]
    pub struct Parser;
}

pub use grammar::Rule;

pub type StandardHeader = http::Header<Range<usize>>;
pub type StandardBody = http::Body<Range<usize>>;
pub type StandardRequest = http::Request<StandardHeader, StandardBody>;
pub type StandardResponse = http::Response<StandardHeader, StandardBody>;

pub type RedactedHeader = http::Header<Option<Range<usize>>>;
pub type RedactedBody = http::Body<Option<Range<usize>>>;
pub type RedactedRequest = http::Request<RedactedHeader, RedactedBody>;
pub type RedactedResponse = http::Response<RedactedHeader, RedactedBody>;

fn parse_request<V, B>(
    input: &str,
    parse_body: impl FnOnce(Pairs<'_, Rule>) -> Result<HashMap<String, B>>,
) -> Result<http::Request<http::Header<V>, B>>
where
    V: HeaderValue,
{
    let pairs = grammar::Parser::parse(Rule::request, input)?;
    parse_http_message(
        pairs,
        |line| {
            parse_three_field_line(
                line,
                Rule::request_line,
                "request_line",
                [
                    (Rule::method, "method"),
                    (Rule::url, "url"),
                    (Rule::protocol_version, "protocol_version"),
                ],
            )
        },
        parse_headers::<V>,
        parse_body,
        |first, headers, body| http::Request {
            method: first.0,
            url: first.1,
            protocol_version: first.2,
            headers,
            body,
        },
    )
}

fn parse_response<V, B>(
    input: &str,
    parse_body: impl FnOnce(Pairs<'_, Rule>) -> Result<HashMap<String, B>>,
) -> Result<http::Response<http::Header<V>, B>>
where
    V: HeaderValue,
{
    let pairs = grammar::Parser::parse(Rule::response, input)?;
    parse_http_message(
        pairs,
        |line| {
            parse_three_field_line(
                line,
                Rule::status_line,
                "status_line",
                [
                    (Rule::protocol_version, "protocol_version"),
                    (Rule::status_code, "status_code"),
                    (Rule::status, "status"),
                ],
            )
        },
        parse_headers::<V>,
        parse_body,
        |first, headers, body| http::Response {
            protocol_version: first.0,
            status_code: first.1,
            status: first.2,
            headers,
            body,
        },
    )
}

pub fn parse_standard_request(input: &str) -> Result<StandardRequest> {
    parse_request(input, parse_standard_body)
}

pub fn parse_standard_response(input: &str) -> Result<StandardResponse> {
    parse_response(input, parse_standard_body)
}

pub fn parse_redacted_request(input: &str) -> Result<RedactedRequest> {
    parse_request(input, parse_redacted_body)
}

pub fn parse_redacted_response(input: &str) -> Result<RedactedResponse> {
    parse_response(input, parse_redacted_body)
}

impl FromStr for StandardRequest {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        parse_standard_request(s)
    }
}

impl FromStr for StandardResponse {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        parse_standard_response(s)
    }
}

impl FromStr for RedactedRequest {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        parse_redacted_request(s)
    }
}

impl FromStr for RedactedResponse {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        parse_redacted_response(s)
    }
}
