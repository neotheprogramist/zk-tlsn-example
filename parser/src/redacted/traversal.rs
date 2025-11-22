use std::collections::HashMap;

use pest::{
    RuleType,
    iterators::{Pair, Pairs},
};

use super::{Body, Header};
use crate::{
    common::{assert_end_of_iterator, assert_rule},
    error::{ParseError, Result},
    path::{PathSegment, PathStack},
    traits::{RangeExtractor, Traverser},
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
    pub pair: R,
}

impl<R: Copy> BodyConfig<R> {
    pub fn new(pair: R) -> Self {
        Self { pair }
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

        assert_rule(&name_pair, config.header_name, "header_name")?;

        let value = if let Some(value_pair) = inner.next() {
            assert_rule(&value_pair, config.header_value, "header_value")?;
            Some(value_pair.extract_range())
        } else {
            None
        };

        assert_end_of_iterator(&mut inner, "header")?;

        Ok(Header {
            name: name_pair.extract_range(),
            value,
        })
    }
}

impl<R: RuleType + PartialEq + Copy> Traverser for HeaderTraverser<'_, R> {
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
    body: HashMap<String, Body>,
    pathstack: PathStack,
    _phantom: std::marker::PhantomData<&'a R>,
}

impl<'a, R: RuleType + PartialEq + Copy> BodyTraverser<'a, R> {
    pub fn new(config: BodyConfig<R>) -> Self {
        Self {
            config,
            body: HashMap::new(),
            pathstack: PathStack::default(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn traverse(
        mut self,
        pairs: impl Iterator<Item = Pair<'a, R>>,
    ) -> Result<HashMap<String, Body>> {
        for pair in pairs {
            if pair.as_rule() != self.config.pair {
                break;
            }

            self.traverse_pair(pair)?;
        }

        Ok(self.body)
    }

    fn traverse_pair(&mut self, pair: Pair<'a, R>) -> Result<()> {
        let mut inner = pair.into_inner();
        let key_pair = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("key in pair".to_string()))?;

        let value = inner.next().map(|v| v.extract_range());

        assert_end_of_iterator(&mut inner, "pair")?;

        let key_str = key_pair.as_str().to_string();
        self.pathstack.push(PathSegment::Key(key_str));

        self.body.insert(
            self.pathstack.to_string(),
            Body::KeyValue {
                key: key_pair.extract_range(),
                value,
            },
        );

        self.pathstack.pop();
        Ok(())
    }
}
