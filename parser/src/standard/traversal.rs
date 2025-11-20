use std::collections::HashMap;

use pest::{
    RuleType,
    iterators::{Pair, Pairs},
};

use crate::{
    common::{assert_end_of_iterator, assert_rule},
    error::{ParseError, Result},
    path::{PathSegment, PathStack},
    traits::{RangeExtractor, Traverser},
    types::{Body, Header},
};

#[derive(Debug, Clone, Copy)]
pub struct HeaderConfig<R> {
    pub headers: R,
    pub header: R,
    pub header_name: R,
    pub header_value: R,
}

impl<R: Copy> HeaderConfig<R> {
    pub fn new(headers: R, header: R, header_name: R, header_value: R) -> Self {
        Self {
            headers,
            header,
            header_name,
            header_value,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BodyConfig<R> {
    pub object: R,
    pub pair: R,
    pub array: R,
}

impl<R: Copy> BodyConfig<R> {
    pub fn new(object: R, pair: R, array: R) -> Self {
        Self {
            object,
            pair,
            array,
        }
    }
}

pub struct HeaderTraverser<'a, R> {
    config: HeaderConfig<R>,
    pairs: Pairs<'a, R>,
    headers: HashMap<String, Vec<Header>>,
}

impl<'a, R: RuleType + PartialEq + Copy> HeaderTraverser<'a, R> {
    pub fn new(config: HeaderConfig<R>, headers_pair: Pair<'a, R>) -> Result<Self> {
        assert_rule(&headers_pair, config.headers, "headers")?;
        Ok(Self {
            config,
            pairs: headers_pair.into_inner(),
            headers: HashMap::new(),
        })
    }

    fn parse_header_inner(pair: Pair<'_, R>, config: &HeaderConfig<R>) -> Result<Header> {
        let mut inner = pair.into_inner();

        let name_pair = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("header name".to_string()))?;
        let value_pair = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("header value".to_string()))?;

        assert_rule(&name_pair, config.header_name, "header_name")?;
        assert_rule(&value_pair, config.header_value, "header_value")?;

        assert_end_of_iterator(&mut inner, "header")?;

        Ok(Header {
            name: name_pair.extract_range(),
            value: Some(value_pair.extract_range()),
        })
    }
}

impl<'a, R: RuleType + PartialEq + Copy> Traverser for HeaderTraverser<'a, R> {
    type Output = Vec<Header>;

    fn traverse(mut self) -> Result<HashMap<String, Self::Output>> {
        for pair in self.pairs.by_ref() {
            assert_rule(&pair, self.config.header, "header")?;

            let name_pair =
                pair.clone().into_inner().next().ok_or_else(|| {
                    ParseError::MissingField("header name in traverse".to_string())
                })?;
            let name = name_pair.as_str().to_lowercase();
            let header = Self::parse_header_inner(pair, &self.config)?;
            self.headers.entry(name).or_default().push(header);
        }

        Ok(self.headers)
    }
}

pub struct BodyTraverser<'a, R> {
    config: BodyConfig<R>,
    root: Pair<'a, R>,
    body: HashMap<String, Body>,
    pathstack: PathStack,
}

impl<'a, R: RuleType + PartialEq + Copy> BodyTraverser<'a, R> {
    pub fn new(config: BodyConfig<R>, body_pair: Pair<'a, R>) -> Result<Self> {
        let rule = body_pair.as_rule();

        if rule != config.object && rule != config.array {
            return Err(ParseError::UnexpectedRule(format!(
                "Standard parser expects object or array at root, got {rule:?}"
            )));
        }

        let mut body = HashMap::new();
        body.insert(String::new(), Body::Value(body_pair.extract_range()));

        Ok(Self {
            config,
            root: body_pair,
            body,
            pathstack: PathStack::default(),
        })
    }

    fn traverse_value(&mut self, value: Pair<'_, R>) -> Result<()> {
        let current_rule = value.as_rule();

        if current_rule == self.config.object {
            self.traverse_object(value)?;
        } else if current_rule == self.config.array {
            self.traverse_array(value)?;
        }

        self.pathstack.pop();
        Ok(())
    }

    fn traverse_object(&mut self, value: Pair<'_, R>) -> Result<()> {
        assert_rule(&value, self.config.object, "object")?;

        for pair in value.into_inner() {
            assert_rule(&pair, self.config.pair, "pair")?;

            let mut inner = pair.into_inner();
            let key_pair = inner
                .next()
                .ok_or_else(|| ParseError::MissingField("object key".to_string()))?;
            let value_pair = inner
                .next()
                .ok_or_else(|| ParseError::MissingField("object value".to_string()))?;

            assert_end_of_iterator(&mut inner, "pair")?;

            let key_str = key_pair.as_str().to_string();
            self.pathstack.push(PathSegment::Key(key_str));

            self.body.insert(
                self.pathstack.to_string(),
                Body::KeyValue {
                    key: key_pair.extract_range(),
                    value: Some(value_pair.extract_range()),
                },
            );

            self.traverse_value(value_pair)?;
        }

        Ok(())
    }

    fn traverse_array(&mut self, value: Pair<'_, R>) -> Result<()> {
        assert_rule(&value, self.config.array, "array")?;

        for (i, pair) in value.into_inner().enumerate() {
            self.pathstack.push(PathSegment::Index(i));
            self.body.insert(
                self.pathstack.to_string(),
                Body::Value(pair.extract_range()),
            );
            self.traverse_value(pair)?;
        }

        Ok(())
    }
}

impl<'a, R: RuleType + PartialEq + Copy> Traverser for BodyTraverser<'a, R> {
    type Output = Body;

    fn traverse(mut self) -> Result<HashMap<String, Self::Output>> {
        self.traverse_value(self.root.clone())?;
        Ok(self.body)
    }
}
