use std::{collections::HashMap, ops::Range};

use pest::{RuleType, iterators::Pairs};

use crate::{
    error::Result,
    traits::RangeExtractor,
    traversal::{BodyConfig, BodyTraverser, HeaderConfig, HeaderTraverser, assert_rule},
    types::{Body, Header},
};

pub trait HttpMessageBuilder: Sized {
    type Rule: RuleType + PartialEq + Copy;
    type Message;

    fn header_config(&self) -> HeaderConfig<Self::Rule>;
    fn body_config(&self) -> BodyConfig<Self::Rule>;
    fn chunk_size_rule(&self) -> Self::Rule;

    fn build_message(
        &self,
        first_line: (Range<usize>, Range<usize>, Range<usize>),
        headers: HashMap<String, Vec<Header>>,
        chunk_size: Range<usize>,
        body: HashMap<String, Body>,
    ) -> Self::Message;

    fn parse_first_line(
        &self,
        pair: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>)>;

    fn parse_headers(
        &self,
        headers_pair: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<HashMap<String, Vec<Header>>> {
        HeaderTraverser::new(self.header_config(), headers_pair)?.traverse()
    }

    fn parse_body(
        &self,
        body_pair: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<HashMap<String, Body>> {
        BodyTraverser::new(self.body_config(), body_pair)?.traverse()
    }

    fn parse(&self, mut pairs: Pairs<'_, Self::Rule>) -> Result<Self::Message> {
        let first_line_pair = pairs
            .next()
            .ok_or_else(|| crate::error::ParseError::MissingField("first line".to_string()))?;
        let headers_pair = pairs
            .next()
            .ok_or_else(|| crate::error::ParseError::MissingField("headers section".to_string()))?;
        let chunk_size_pair = pairs.next().ok_or_else(|| {
            crate::error::ParseError::MissingField("chunk size or body".to_string())
        })?;
        let body_pair = pairs
            .next()
            .ok_or_else(|| crate::error::ParseError::MissingField("body".to_string()))?;

        assert_rule(&chunk_size_pair, self.chunk_size_rule(), "chunk_size")?;

        let first_line = self.parse_first_line(first_line_pair)?;
        let headers = self.parse_headers(headers_pair)?;
        let chunk_size = chunk_size_pair.extract_range();
        let body = self.parse_body(body_pair)?;

        Ok(self.build_message(first_line, headers, chunk_size, body))
    }
}
