use std::{collections::HashMap, ops::Range};

use pest::{
    RuleType,
    iterators::{Pair, Pairs},
};

use crate::error::{ParseError, Result};

pub fn assert_rule<R: RuleType + PartialEq>(
    pair: &Pair<'_, R>,
    expected: R,
    field: &str,
) -> Result<()> {
    if pair.as_rule() != expected {
        return Err(ParseError::UnexpectedRule(format!(
            "Expected {}, got {:?}",
            field,
            pair.as_rule()
        )));
    }
    Ok(())
}

pub fn assert_end_of_iterator<'a, R: RuleType>(
    iter: &mut impl Iterator<Item = Pair<'a, R>>,
    context: &str,
) -> Result<()> {
    if iter.next().is_some() {
        return Err(ParseError::UnexpectedRule(format!(
            "Expected end of iterator in {context}, but found additional elements"
        )));
    }
    Ok(())
}

pub trait HttpMessageBuilder: Sized {
    type Rule: RuleType + PartialEq + Copy;
    type Message;
    type Header;
    type Body;

    fn build_message(
        &self,
        first_line: (Range<usize>, Range<usize>, Range<usize>),
        headers: HashMap<String, Vec<Self::Header>>,
        chunk_size: Range<usize>,
        body: HashMap<String, Self::Body>,
    ) -> Self::Message;

    fn parse_first_line(
        &self,
        pair: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>)>;

    fn parse(&self, pairs: Pairs<'_, Self::Rule>) -> Result<Self::Message>;
}
