use std::{collections::HashMap, ops::Range};

use crate::{
    error::ParserError,
    ranged::{RangedText, RangedValue},
    standard::{Request, Response},
};

mod json_syntax {
    pub const KEY_QUOTE_OPEN: usize = 1;
    pub const KEY_QUOTE_CLOSE: usize = 1;
    pub const COLON_SEPARATOR: usize = 1;

    pub fn key_prefix_length(key_len: usize) -> usize {
        KEY_QUOTE_OPEN + key_len + KEY_QUOTE_CLOSE + COLON_SEPARATOR
    }
}

#[derive(Debug, Clone)]
enum PathSegment {
    Key(String),
    Index(usize),
}

impl PathSegment {
    fn to_path_string(segments: &[PathSegment]) -> String {
        let mut result = String::new();
        for (i, segment) in segments.iter().enumerate() {
            match segment {
                PathSegment::Key(key) => {
                    if i > 0 {
                        result.push('.');
                    }
                    result.push_str(key);
                }
                PathSegment::Index(idx) => {
                    result.push_str(&format!("[{}]", idx));
                }
            }
        }
        result
    }
}

struct WorkItem<'a> {
    value: &'a RangedValue,
    path: Vec<PathSegment>,
}

pub trait HeaderSearchable {
    fn get_headers(&self) -> &HashMap<String, RangedText>;

    fn get_header_ranges(&self, header_names: &[&str]) -> Result<Vec<Range<usize>>, ParserError> {
        let mut ranges = Vec::new();

        for name in header_names {
            if let Some(header) = self.get_headers().get(*name) {
                ranges.push(header.range.clone());
            } else {
                return Err(ParserError::HeaderNotFound(name.to_string()));
            }
        }

        Ok(ranges)
    }
}

pub trait BodySearchable {
    fn get_body(&self) -> Result<&RangedValue, ParserError>;

    fn get_body_keypaths_ranges(
        &self,
        keypaths: &[&str],
    ) -> Result<Vec<Range<usize>>, ParserError> {
        let body = self.get_body()?;
        let all_ranges = Self::collect_body_ranges(body);

        let mut result = Vec::new();
        for keypath in keypaths {
            if let Some(range) = all_ranges.get(*keypath) {
                result.push(range.clone());
            } else {
                return Err(ParserError::KeypathNotFound(keypath.to_string()));
            }
        }
        Ok(result)
    }

    fn collect_body_ranges(body: &RangedValue) -> HashMap<String, Range<usize>> {
        let mut ranges = HashMap::new();
        let mut stack = vec![WorkItem {
            value: body,
            path: Vec::new(),
        }];

        while let Some(WorkItem { value, path }) = stack.pop() {
            match value {
                RangedValue::Object { value: obj, .. } => {
                    for (key, val) in obj {
                        let mut new_path = path.clone();
                        new_path.push(PathSegment::Key(key.clone()));

                        let path_str = PathSegment::to_path_string(&new_path);

                        let key_prefix_len = json_syntax::key_prefix_length(key.len());
                        let value_start = val.get_range().start;
                        let value_end = val.get_range().end;
                        let range_with_key = value_start.saturating_sub(key_prefix_len)..value_end;

                        ranges.insert(path_str, range_with_key);

                        stack.push(WorkItem {
                            value: val,
                            path: new_path,
                        });
                    }
                }
                RangedValue::Array { value: arr, .. } => {
                    for (index, item) in arr.iter().enumerate() {
                        let mut new_path = path.clone();
                        new_path.push(PathSegment::Index(index));

                        let path_str = PathSegment::to_path_string(&new_path);
                        let range = item.get_range();
                        ranges.insert(path_str, range);

                        stack.push(WorkItem {
                            value: item,
                            path: new_path,
                        });
                    }
                }
                _ => {}
            }
        }

        ranges
    }
}

impl HeaderSearchable for Request {
    fn get_headers(&self) -> &HashMap<String, RangedText> {
        &self.headers
    }
}

impl HeaderSearchable for Response {
    fn get_headers(&self) -> &HashMap<String, RangedText> {
        &self.headers
    }
}

impl BodySearchable for Request {
    fn get_body(&self) -> Result<&RangedValue, ParserError> {
        self.body
            .as_ref()
            .ok_or(ParserError::MissingField("request body"))
    }
}

impl BodySearchable for Response {
    fn get_body(&self) -> Result<&RangedValue, ParserError> {
        Ok(&self.body)
    }
}

impl Request {
    pub fn get_request_line_range(&self) -> Range<usize> {
        self.request_line.range.clone()
    }
}

impl Response {
    pub fn get_status_line_range(&self) -> Range<usize> {
        self.status_line.range.clone()
    }
}
