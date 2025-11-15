use std::{collections::HashMap, ops::Range};

use crate::types::{RangedHeader, RangedValue, Request, Response};

pub trait HeaderSearchable {
    fn get_headers(&self) -> &HashMap<String, RangedHeader>;

    fn get_header_ranges(&self, header_names: &[&str]) -> Vec<Range<usize>> {
        let mut ranges = Vec::new();

        for (key, header) in self.get_headers() {
            if header_names.contains(&key.as_str()) {
                ranges.push(header.range.clone());
            }
        }

        ranges
    }
}

pub trait BodySearchable {
    fn get_body(&self) -> &RangedValue;

    fn get_body_keypaths_ranges(&self, keypaths: &[&str]) -> Vec<Range<usize>> {
        let mut ranges = Vec::new();
        Self::search_body_by_path(keypaths, self.get_body(), Vec::new(), &mut ranges);
        ranges
    }

    fn search_body_by_path(
        keypaths: &[&str],
        body: &RangedValue,
        current_path: Vec<String>,
        ranges: &mut Vec<Range<usize>>,
    ) {
        match body {
            RangedValue::Object { value, .. } => {
                for (key, val) in value {
                    let mut new_path = current_path.clone();
                    new_path.push(key.clone());
                    let path_str = new_path.join(".");

                    if keypaths.contains(&path_str.as_str()) {
                        let start = val.get_range().start;
                        let end = val.get_range().end;
                        ranges.push((start.saturating_sub(key.len() + 3))..end);
                    }

                    Self::search_body_by_path(keypaths, val, new_path, ranges);
                }
            }
            RangedValue::Array { value, .. } => {
                for item in value {
                    Self::search_body_by_path(keypaths, item, current_path.clone(), ranges);
                }
            }
            _ => {}
        }
    }
}

impl HeaderSearchable for Request {
    fn get_headers(&self) -> &HashMap<String, RangedHeader> {
        &self.headers
    }
}

impl HeaderSearchable for Response {
    fn get_headers(&self) -> &HashMap<String, RangedHeader> {
        &self.headers
    }
}

impl BodySearchable for Response {
    fn get_body(&self) -> &RangedValue {
        &self.body
    }
}

impl Request {
    pub fn get_request_line_range(&self) -> Range<usize> {
        self.request_line.range.clone()
    }

    pub fn get_body_keypaths_ranges(&self, keypaths: &[&str]) -> Vec<Range<usize>> {
        if let Some(body) = &self.body {
            let mut ranges = Vec::new();
            Self::search_body_by_path(keypaths, body, Vec::new(), &mut ranges);
            ranges
        } else {
            Vec::new()
        }
    }

    fn search_body_by_path(
        keypaths: &[&str],
        body: &RangedValue,
        current_path: Vec<String>,
        ranges: &mut Vec<Range<usize>>,
    ) {
        match body {
            RangedValue::Object { value, .. } => {
                for (key, val) in value {
                    let mut new_path = current_path.clone();
                    new_path.push(key.clone());
                    let path_str = new_path.join(".");

                    if keypaths.contains(&path_str.as_str()) {
                        let start = val.get_range().start;
                        let end = val.get_range().end;
                        ranges.push((start.saturating_sub(key.len() + 3))..end);
                    }

                    Self::search_body_by_path(keypaths, val, new_path, ranges);
                }
            }
            RangedValue::Array { value, .. } => {
                for item in value {
                    Self::search_body_by_path(keypaths, item, current_path.clone(), ranges);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            RangedHeader {
                range: 0..10,
                value: "application/json".to_string(),
            },
        );

        let response = Response::new(headers, RangedValue::default());
        let ranges = response.get_header_ranges(&["Content-Type"]);

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 0..10);
    }

    #[test]
    fn test_search_nested_keypaths() {
        let mut inner_obj = HashMap::new();
        inner_obj.insert(
            "name".to_string(),
            RangedValue::String {
                range: 20..30,
                value: "Alice".to_string(),
            },
        );

        let mut outer_obj = HashMap::new();
        outer_obj.insert(
            "user".to_string(),
            RangedValue::Object {
                range: 10..40,
                value: inner_obj,
            },
        );

        let content = RangedValue::Object {
            range: 0..50,
            value: outer_obj,
        };

        let response = Response::new(HashMap::new(), content);
        let ranges = response.get_body_keypaths_ranges(&["user.name"]);

        assert_eq!(ranges.len(), 1);
        // Should include key and value
        assert!(ranges[0].start <= 20);
        assert_eq!(ranges[0].end, 30);
    }
}
