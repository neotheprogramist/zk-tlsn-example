use std::{collections::HashMap, ops::Range};

use crate::{
    error::ParserError,
    types::{RangedHeader, RangedValue, Request, Response},
};

pub trait HeaderSearchable {
    fn get_headers(&self) -> &HashMap<String, RangedHeader>;

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
        let mut all_ranges = HashMap::new();
        Self::collect_body_ranges(body, Vec::new(), &mut all_ranges);

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

    fn collect_body_ranges(
        body: &RangedValue,
        current_path: Vec<String>,
        ranges: &mut HashMap<String, Range<usize>>,
    ) {
        match body {
            RangedValue::Object { value, .. } => {
                for (key, val) in value {
                    let mut new_path = current_path.clone();
                    new_path.push(key.clone());
                    let path_str = new_path.join(".");

                    let start = val.get_range().start;
                    let end = val.get_range().end;
                    ranges.insert(path_str.clone(), (start.saturating_sub(key.len() + 3))..end);

                    Self::collect_body_ranges(val, new_path, ranges);
                }
            }
            RangedValue::Array { value, .. } => {
                for item in value {
                    Self::collect_body_ranges(item, current_path.clone(), ranges);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_request_with_content(content: RangedValue) -> Request {
        let request_line = RangedHeader {
            range: 0..24,
            value: "GET /api/test HTTP/1.1".to_string(),
        };

        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            RangedHeader {
                range: 25..40,
                value: "example.com".to_string(),
            },
        );

        Request::new(request_line, headers, Some(content))
    }

    fn create_test_response_with_content(content: RangedValue) -> Response {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            RangedHeader {
                range: 0..30,
                value: "application/json".to_string(),
            },
        );

        Response::new(headers, content)
    }

    #[test]
    fn test_search_single_header() {
        let request = create_test_request_with_content(RangedValue::default());
        let header_ranges = request.get_header_ranges(&["Host"]).unwrap();

        assert_eq!(header_ranges.len(), 1);
        assert_eq!(header_ranges[0], 25..40);
    }

    #[test]
    fn test_search_multiple_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            RangedHeader {
                range: 0..20,
                value: "example.com".to_string(),
            },
        );
        headers.insert(
            "User-Agent".to_string(),
            RangedHeader {
                range: 21..50,
                value: "TestClient".to_string(),
            },
        );

        let response = Response::new(headers, RangedValue::default());
        let header_ranges = response.get_header_ranges(&["Host", "User-Agent"]).unwrap();

        assert_eq!(header_ranges.len(), 2);
    }

    #[test]
    fn test_search_non_existent_header() {
        let request = create_test_request_with_content(RangedValue::default());
        let result = request.get_header_ranges(&["NonExistent"]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParserError::HeaderNotFound(_)
        ));
    }

    #[test]
    fn test_search_simple_keypath() {
        let mut obj = HashMap::new();
        obj.insert(
            "name".to_string(),
            RangedValue::String {
                range: 100..110,
                value: "Alice".to_string(),
            },
        );

        let content = RangedValue::Object {
            range: 90..120,
            value: obj,
        };

        let request = create_test_request_with_content(content);
        let body_ranges = request.get_body_keypaths_ranges(&["name"]).unwrap();

        assert_eq!(body_ranges.len(), 1);
    }

    #[test]
    fn test_search_nested_keypath() {
        let mut profile = HashMap::new();
        profile.insert(
            "age".to_string(),
            RangedValue::Number {
                range: 150..153,
                value: 30.0,
            },
        );

        let mut user = HashMap::new();
        user.insert(
            "profile".to_string(),
            RangedValue::Object {
                range: 140..160,
                value: profile,
            },
        );

        let content = RangedValue::Object {
            range: 100..170,
            value: user,
        };

        let response = create_test_response_with_content(content);
        let ranges = response.get_body_keypaths_ranges(&["profile.age"]).unwrap();

        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_search_multiple_keypaths() {
        let mut obj = HashMap::new();
        obj.insert(
            "name".to_string(),
            RangedValue::String {
                range: 100..110,
                value: "Bob".to_string(),
            },
        );
        obj.insert(
            "age".to_string(),
            RangedValue::Number {
                range: 120..123,
                value: 25.0,
            },
        );

        let content = RangedValue::Object {
            range: 90..130,
            value: obj,
        };

        let request = create_test_request_with_content(content);
        let body_ranges = request.get_body_keypaths_ranges(&["name", "age"]).unwrap();

        assert_eq!(body_ranges.len(), 2);
    }

    #[test]
    fn test_search_array_does_not_match_keypath() {
        let array = RangedValue::Array {
            range: 100..120,
            value: vec![
                RangedValue::Number {
                    range: 101..104,
                    value: 1.0,
                },
                RangedValue::Number {
                    range: 106..109,
                    value: 2.0,
                },
            ],
        };

        let response = create_test_response_with_content(array);
        let result = response.get_body_keypaths_ranges(&["items"]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParserError::KeypathNotFound(_)
        ));
    }

    #[test]
    fn test_search_deeply_nested_keypath() {
        let mut level3 = HashMap::new();
        level3.insert(
            "value".to_string(),
            RangedValue::String {
                range: 200..210,
                value: "deep".to_string(),
            },
        );

        let mut level2 = HashMap::new();
        level2.insert(
            "level3".to_string(),
            RangedValue::Object {
                range: 190..220,
                value: level3,
            },
        );

        let mut level1 = HashMap::new();
        level1.insert(
            "level2".to_string(),
            RangedValue::Object {
                range: 180..230,
                value: level2,
            },
        );

        let content = RangedValue::Object {
            range: 170..240,
            value: level1,
        };

        let request = create_test_request_with_content(content);
        let body_ranges = request
            .get_body_keypaths_ranges(&["level2.level3.value"])
            .unwrap();

        assert_eq!(body_ranges.len(), 1);
    }

    #[test]
    fn test_search_combined_headers_and_keypaths() {
        let mut obj = HashMap::new();
        obj.insert(
            "id".to_string(),
            RangedValue::Number {
                range: 100..103,
                value: 123.0,
            },
        );

        let content = RangedValue::Object {
            range: 90..110,
            value: obj,
        };

        let request = create_test_request_with_content(content);
        let mut ranges = Vec::new();
        ranges.extend(request.get_header_ranges(&["Host"]).unwrap());
        ranges.extend(request.get_body_keypaths_ranges(&["id"]).unwrap());

        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_search_object_in_array() {
        let mut item1 = HashMap::new();
        item1.insert(
            "name".to_string(),
            RangedValue::String {
                range: 110..120,
                value: "Item1".to_string(),
            },
        );

        let mut item2 = HashMap::new();
        item2.insert(
            "name".to_string(),
            RangedValue::String {
                range: 140..150,
                value: "Item2".to_string(),
            },
        );

        let mut outer = HashMap::new();
        outer.insert(
            "items".to_string(),
            RangedValue::Array {
                range: 100..160,
                value: vec![
                    RangedValue::Object {
                        range: 105..125,
                        value: item1,
                    },
                    RangedValue::Object {
                        range: 135..155,
                        value: item2,
                    },
                ],
            },
        );

        let content = RangedValue::Object {
            range: 90..170,
            value: outer,
        };

        let response = create_test_response_with_content(content);
        let ranges = response.get_body_keypaths_ranges(&["items"]).unwrap();

        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_search_preserves_order_with_duplicates() {
        let mut obj = HashMap::new();
        obj.insert(
            "data".to_string(),
            RangedValue::String {
                range: 100..110,
                value: "test".to_string(),
            },
        );

        let content = RangedValue::Object {
            range: 90..120,
            value: obj,
        };

        let request = create_test_request_with_content(content);

        // When the same keypath is requested twice, it should appear twice in the result
        let ranges = request.get_body_keypaths_ranges(&["data", "data"]).unwrap();

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], ranges[1]);
    }

    #[test]
    fn test_search_partial_keypath_no_match() {
        let mut level2 = HashMap::new();
        level2.insert(
            "value".to_string(),
            RangedValue::String {
                range: 110..120,
                value: "test".to_string(),
            },
        );

        let mut level1 = HashMap::new();
        level1.insert(
            "level2".to_string(),
            RangedValue::Object {
                range: 100..130,
                value: level2,
            },
        );

        let content = RangedValue::Object {
            range: 90..140,
            value: level1,
        };

        let response = create_test_response_with_content(content);

        let ranges = response.get_body_keypaths_ranges(&["level2"]).unwrap();

        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_search_empty_keypaths_and_headers() {
        let request = create_test_request_with_content(RangedValue::default());
        let header_ranges = request.get_header_ranges(&[]).unwrap();
        let body_ranges = request.get_body_keypaths_ranges(&[]).unwrap();

        assert_eq!(header_ranges.len(), 0);
        assert_eq!(body_ranges.len(), 0);
    }

    #[test]
    fn test_request_line_range() {
        let content = RangedValue::Object {
            range: 100..110,
            value: HashMap::new(),
        };

        let request = create_test_request_with_content(content);
        let range = request.get_request_line_range();

        assert_eq!(range, 0..24);
    }
}
