use std::{collections::HashMap, ops::Range};

use pest::{
    RuleType,
    iterators::{Pair, Pairs},
};

use crate::parser::{
    error::{ParseError, Result},
    traits::RangeExtractor,
};

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

pub fn parse_three_field_line<R: RuleType + PartialEq>(
    line: Pair<'_, R>,
    line_rule: R,
    line_label: &'static str,
    fields: [(R, &'static str); 3],
) -> Result<(Range<usize>, Range<usize>, Range<usize>)> {
    assert_rule(&line, line_rule, line_label)?;
    let mut inner = line.into_inner();
    let [a, b, c] = fields.map(|(rule, label)| {
        inner
            .next()
            .ok_or_else(|| ParseError::MissingField(label.to_string()))
            .and_then(|pair| {
                assert_rule(&pair, rule, label)?;
                Ok(pair)
            })
    });
    let a = a?;
    let b = b?;
    let c = c?;
    assert_end_of_iterator(&mut inner, line_label)?;
    Ok((a.extract_range(), b.extract_range(), c.extract_range()))
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
        body: HashMap<String, Self::Body>,
    ) -> Self::Message;

    fn parse_first_line(
        &self,
        pair: pest::iterators::Pair<'_, Self::Rule>,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>)>;

    fn parse(&self, pairs: Pairs<'_, Self::Rule>) -> Result<Self::Message>;
}
