use std::collections::HashMap;

use pest::{RuleType, iterators::Pair};

use crate::{
    error::ParserError,
    ranged::{RangedText, RangedValue},
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommonRuleType {
    Object,
    Array,
    String,
    Number,
    Boolean,
    Null,
}

pub trait CommonRule: RuleType {
    fn rule_type(&self) -> Result<CommonRuleType, ParserError>;
}

pub struct CommonParser;

impl CommonParser {
    pub fn parse_header<R: CommonRule>(pair: Pair<R>) -> Result<(String, RangedText), ParserError> {
        let range = pair.as_span().start()..pair.as_span().end();
        let mut inner = pair.into_inner();

        let key = inner
            .next()
            .ok_or(ParserError::MissingField("header key"))?
            .as_str()
            .to_string();

        let value = inner
            .next()
            .ok_or(ParserError::MissingField("header value"))?
            .as_str()
            .to_string();

        Ok((key, RangedText { range, value }))
    }

    pub fn parse_value<R: CommonRule>(pair: Pair<R>) -> Result<RangedValue, ParserError> {
        let range = pair.as_span().start()..pair.as_span().end();

        match pair.as_rule().rule_type()? {
            CommonRuleType::Object => {
                let mut map = HashMap::new();
                for p in pair.into_inner() {
                    let (key, value) = Self::parse_object_entry(p)?;
                    map.insert(key, value);
                }
                Ok(RangedValue::Object { range, value: map })
            }
            CommonRuleType::Array => {
                let mut values = Vec::new();
                for p in pair.into_inner() {
                    values.push(Self::parse_value(p)?);
                }
                Ok(RangedValue::Array {
                    range,
                    value: values,
                })
            }
            CommonRuleType::String => Ok(RangedValue::String {
                range,
                value: pair
                    .into_inner()
                    .next()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default(),
            }),
            CommonRuleType::Number => Ok(RangedValue::Number {
                range,
                value: pair.as_str().parse()?,
            }),
            CommonRuleType::Boolean => Ok(RangedValue::Bool {
                range,
                value: pair.as_str().parse()?,
            }),
            CommonRuleType::Null => Ok(RangedValue::Null),
        }
    }

    pub fn parse_pair<R: CommonRule>(pair: Pair<R>) -> Result<(String, RangedValue), ParserError> {
        let pair_span = pair.as_span();
        let mut inner = pair.into_inner();

        let key_pair = inner.next().ok_or(ParserError::MissingField("pair key"))?;
        let key = key_pair
            .into_inner()
            .next()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default();

        let value_pair = inner
            .next()
            .ok_or(ParserError::MissingField("pair value"))?;

        let value = Self::parse_value_with_span(value_pair, pair_span)?;

        Ok((key, value))
    }

    fn parse_value_with_span<R: CommonRule>(
        pair: Pair<R>,
        span: pest::Span,
    ) -> Result<RangedValue, ParserError> {
        let range = span.start()..span.end();

        match pair.as_rule().rule_type()? {
            CommonRuleType::Object => {
                let mut map = HashMap::new();
                for p in pair.into_inner() {
                    let (key, value) = Self::parse_object_entry(p)?;
                    map.insert(key, value);
                }
                Ok(RangedValue::Object { range, value: map })
            }
            CommonRuleType::Array => {
                let mut values = Vec::new();
                for p in pair.into_inner() {
                    values.push(Self::parse_value(p)?);
                }
                Ok(RangedValue::Array {
                    range,
                    value: values,
                })
            }
            CommonRuleType::String => Ok(RangedValue::String {
                range,
                value: pair
                    .into_inner()
                    .next()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default(),
            }),
            CommonRuleType::Number => Ok(RangedValue::Number {
                range,
                value: pair.as_str().parse()?,
            }),
            CommonRuleType::Boolean => Ok(RangedValue::Bool {
                range,
                value: pair.as_str().parse()?,
            }),
            CommonRuleType::Null => Ok(RangedValue::Null),
        }
    }

    fn parse_object_entry<R: CommonRule>(
        pair: Pair<R>,
    ) -> Result<(String, RangedValue), ParserError> {
        let mut inner_rules = pair.into_inner();

        let key = inner_rules
            .next()
            .ok_or(ParserError::MissingField("object entry key"))?
            .into_inner()
            .next()
            .ok_or(ParserError::MissingField("inner object entry key"))?
            .as_str()
            .to_string();

        let value = Self::parse_value(
            inner_rules
                .next()
                .ok_or(ParserError::MissingField("object entry value"))?,
        )?;

        Ok((key, value))
    }
}
