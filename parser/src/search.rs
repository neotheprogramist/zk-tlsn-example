use std::{collections::HashMap, ops::Range};

use crate::{
    error::ParserError,
    types::{RangedText, RangedValue, Request, Response},
};

/// JSON key-value syntax: `"key":value`
mod json_syntax {
    pub const KEY_QUOTE_OPEN: usize = 1;
    pub const KEY_QUOTE_CLOSE: usize = 1;
    pub const COLON_SEPARATOR: usize = 1;

    /// Calculates offset to include `"key":` before value
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

    /// Extracts byte ranges for JSON keypaths using simplified dot and array index notation.
    ///
    /// # Keypath Syntax
    ///
    /// This implementation uses a **simplified keypath syntax** intentionally divergent from
    /// RFC 9535 (JSONPath) for the specific use case of TLS notarization, where we need
    /// precise byte ranges for known field paths.
    ///
    /// **Supported syntax:**
    /// - Simple keys: `"username"`, `"balance"`, `"status"`
    /// - Nested keys: `"user.name"`, `"user.profile.age"`, `"data.items"`
    /// - Array indexing: `"[0]"`, `"items[0]"`, `"users[1].name"`
    /// - Nested arrays: `"matrix[0][1]"`, `"data[0].values[2]"`
    ///
    /// **Not supported (RFC 9535 features):**
    /// - Root identifier: `$` (not required)
    /// - Bracket notation for keys: `$['key']`
    /// - Negative indexing: `$[-1]`
    /// - Array slicing: `$[1:3]`
    /// - Wildcards: `[*]`
    /// - Recursive descent: `..`
    /// - Filter expressions: `?<expr>`
    ///
    /// # Design Rationale
    ///
    /// The simplified syntax is intentional because:
    /// 1. TLS notarization requires exact byte ranges for specific known fields
    /// 2. Wildcards and filters would return multiple ranges, complicating notarization
    /// 3. All practical use cases involve direct object/array element access
    /// 4. Simpler implementation reduces attack surface for security-critical code
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

                        // Include "key":value for TLS notarization
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
                // Primitive values (String, Number, Boolean, Null) are leaf nodes.
                // Their ranges were already inserted when processing from parent Object/Array.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_syntax_key_prefix_length() {
        let key = "username";
        let prefix_len = json_syntax::key_prefix_length(key.len());

        assert_eq!(prefix_len, 11); // "username": = 11 chars
        assert_eq!(prefix_len, 1 + key.len() + 1 + 1);

        assert_eq!(json_syntax::key_prefix_length(0), 3);
        assert_eq!(json_syntax::key_prefix_length(1), 4);
        assert_eq!(json_syntax::key_prefix_length(5), 8);

        assert_eq!(
            json_syntax::key_prefix_length(key.len()),
            json_syntax::KEY_QUOTE_OPEN
                + key.len()
                + json_syntax::KEY_QUOTE_CLOSE
                + json_syntax::COLON_SEPARATOR
        );
    }

    #[test]
    fn test_range_includes_json_key_prefix() {
        let json = r#"{"username":"alice","balance":100}"#;
        let key = "username";
        let value_start: usize = 12;
        let value_end: usize = 19;

        let key_prefix_len = json_syntax::key_prefix_length(key.len());
        let range_with_key_start = value_start.saturating_sub(key_prefix_len);

        assert_eq!(range_with_key_start, 1);
        assert_eq!(
            &json[range_with_key_start..value_end],
            r#""username":"alice""#
        );
        assert_eq!(key_prefix_len, 11);
        assert_eq!(value_start - key_prefix_len, 1);
    }

    fn create_test_request_with_content(content: RangedValue) -> Request {
        let request_line = RangedText {
            range: 0..24,
            value: "GET /api/test HTTP/1.1".to_string(),
        };

        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            RangedText {
                range: 25..40,
                value: "example.com".to_string(),
            },
        );

        Request::new(request_line, headers, Some(content))
    }

    fn create_test_response_with_content(content: RangedValue) -> Response {
        let status_line = RangedText {
            range: 0..15,
            value: "HTTP/1.1 200 OK".to_string(),
        };

        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            RangedText {
                range: 16..46,
                value: "application/json".to_string(),
            },
        );

        Response::new(status_line, headers, content)
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
        let status_line = RangedText {
            range: 0..15,
            value: "HTTP/1.1 200 OK".to_string(),
        };

        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            RangedText {
                range: 16..36,
                value: "example.com".to_string(),
            },
        );
        headers.insert(
            "User-Agent".to_string(),
            RangedText {
                range: 37..66,
                value: "TestClient".to_string(),
            },
        );

        let response = Response::new(status_line, headers, RangedValue::default());
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

    #[test]
    fn test_array_indexing_simple() {
        // Test simple array: [1, 2, 3]
        let array = RangedValue::Array {
            range: 100..120,
            value: vec![
                RangedValue::Number {
                    range: 101..102,
                    value: 1.0,
                },
                RangedValue::Number {
                    range: 104..105,
                    value: 2.0,
                },
                RangedValue::Number {
                    range: 107..108,
                    value: 3.0,
                },
            ],
        };

        let response = create_test_response_with_content(array);
        let ranges = response
            .get_body_keypaths_ranges(&["[0]", "[1]", "[2]"])
            .unwrap();

        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], 101..102);
        assert_eq!(ranges[1], 104..105);
        assert_eq!(ranges[2], 107..108);
    }

    #[test]
    fn test_array_indexing_with_objects() {
        // Test array of objects: [{"id":1}, {"id":2}]
        let mut obj1 = HashMap::new();
        obj1.insert(
            "id".to_string(),
            RangedValue::Number {
                range: 112..113,
                value: 1.0,
            },
        );

        let mut obj2 = HashMap::new();
        obj2.insert(
            "id".to_string(),
            RangedValue::Number {
                range: 125..126,
                value: 2.0,
            },
        );

        let array = RangedValue::Array {
            range: 100..140,
            value: vec![
                RangedValue::Object {
                    range: 105..118,
                    value: obj1,
                },
                RangedValue::Object {
                    range: 120..133,
                    value: obj2,
                },
            ],
        };

        let request = create_test_request_with_content(array);

        // Access array elements
        let ranges = request.get_body_keypaths_ranges(&["[0]", "[1]"]).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 105..118);
        assert_eq!(ranges[1], 120..133);

        // Access nested fields in array elements
        let ranges = request
            .get_body_keypaths_ranges(&["[0].id", "[1].id"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
        // Note: The range includes the key name, so it starts before the value
        assert!(ranges[0].contains(&112));
        assert!(ranges[1].contains(&125));
    }

    #[test]
    fn test_nested_array_in_object() {
        // Test object with array field: {"items":[{"name":"A"}, {"name":"B"}]}
        let mut item1 = HashMap::new();
        item1.insert(
            "name".to_string(),
            RangedValue::String {
                range: 220..221,
                value: "A".to_string(),
            },
        );

        let mut item2 = HashMap::new();
        item2.insert(
            "name".to_string(),
            RangedValue::String {
                range: 240..241,
                value: "B".to_string(),
            },
        );

        let mut outer = HashMap::new();
        outer.insert(
            "items".to_string(),
            RangedValue::Array {
                range: 200..260,
                value: vec![
                    RangedValue::Object {
                        range: 210..225,
                        value: item1,
                    },
                    RangedValue::Object {
                        range: 230..245,
                        value: item2,
                    },
                ],
            },
        );

        let content = RangedValue::Object {
            range: 190..270,
            value: outer,
        };

        let response = create_test_response_with_content(content);

        // Access the items array
        let ranges = response.get_body_keypaths_ranges(&["items"]).unwrap();
        assert_eq!(ranges.len(), 1);
        // The range includes the key name: "items":[...]
        // "items" = 5 chars, plus ":" = 1, plus quotes = 2, total subtract 8
        // But saturating_sub(5 + 3) = 8, so 200 - 8 = 192
        assert_eq!(ranges[0], 192..260);

        // Access array elements via items
        let ranges = response
            .get_body_keypaths_ranges(&["items[0]", "items[1]"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 210..225);
        assert_eq!(ranges[1], 230..245);

        // Access nested fields in array elements
        let ranges = response
            .get_body_keypaths_ranges(&["items[0].name", "items[1].name"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
        assert!(ranges[0].contains(&220));
        assert!(ranges[1].contains(&240));
    }

    #[test]
    fn test_array_indexing_out_of_bounds() {
        let array = RangedValue::Array {
            range: 100..120,
            value: vec![RangedValue::Number {
                range: 101..102,
                value: 1.0,
            }],
        };

        let response = create_test_response_with_content(array);
        let result = response.get_body_keypaths_ranges(&["[5]"]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParserError::KeypathNotFound(_)
        ));
    }

    #[test]
    fn test_deeply_nested_arrays() {
        // Test [[1, 2], [3, 4]]
        let inner1 = RangedValue::Array {
            range: 305..315,
            value: vec![
                RangedValue::Number {
                    range: 306..307,
                    value: 1.0,
                },
                RangedValue::Number {
                    range: 309..310,
                    value: 2.0,
                },
            ],
        };

        let inner2 = RangedValue::Array {
            range: 320..330,
            value: vec![
                RangedValue::Number {
                    range: 321..322,
                    value: 3.0,
                },
                RangedValue::Number {
                    range: 324..325,
                    value: 4.0,
                },
            ],
        };

        let outer = RangedValue::Array {
            range: 300..340,
            value: vec![inner1, inner2],
        };

        let request = create_test_request_with_content(outer);

        // Access outer array elements
        let ranges = request.get_body_keypaths_ranges(&["[0]", "[1]"]).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 305..315);
        assert_eq!(ranges[1], 320..330);

        // Access nested array elements
        let ranges = request
            .get_body_keypaths_ranges(&["[0][0]", "[0][1]", "[1][0]", "[1][1]"])
            .unwrap();
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0], 306..307);
        assert_eq!(ranges[1], 309..310);
        assert_eq!(ranges[2], 321..322);
        assert_eq!(ranges[3], 324..325);
    }

    #[test]
    fn test_single_field_extraction() {
        let body = RangedValue::Object {
            range: 0..30,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "username".to_string(),
                    RangedValue::String {
                        range: 12..19,
                        value: "alice".to_string(),
                    },
                );
                map
            },
        };

        let request = create_test_request_with_content(body);
        let ranges = request.get_body_keypaths_ranges(&["username"]).unwrap();
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_multiple_fields_extraction() {
        let body = RangedValue::Object {
            range: 0..40,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "username".to_string(),
                    RangedValue::String {
                        range: 12..19,
                        value: "alice".to_string(),
                    },
                );
                map.insert(
                    "balance".to_string(),
                    RangedValue::Number {
                        range: 30..33,
                        value: 100.0,
                    },
                );
                map
            },
        };

        let request = create_test_request_with_content(body);
        let ranges = request
            .get_body_keypaths_ranges(&["username", "balance"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_nested_fields_extraction() {
        let profile = RangedValue::Object {
            range: 70..120,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "name".to_string(),
                    RangedValue::String {
                        range: 80..85,
                        value: "Bob".to_string(),
                    },
                );
                map.insert(
                    "age".to_string(),
                    RangedValue::Number {
                        range: 95..97,
                        value: 25.0,
                    },
                );
                map
            },
        };

        let user = RangedValue::Object {
            range: 50..130,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert("profile".to_string(), profile);
                map
            },
        };

        let body = RangedValue::Object {
            range: 0..150,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert("user".to_string(), user);
                map
            },
        };

        let request = create_test_request_with_content(body);
        let ranges = request
            .get_body_keypaths_ranges(&["user.profile.name", "user.profile.age"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_array_elements_extraction() {
        let array = RangedValue::Array {
            range: 10..50,
            value: vec![
                RangedValue::String {
                    range: 11..16,
                    value: "item1".to_string(),
                },
                RangedValue::String {
                    range: 18..23,
                    value: "item2".to_string(),
                },
            ],
        };

        let body = RangedValue::Object {
            range: 0..60,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert("items".to_string(), array);
                map
            },
        };

        let response = create_test_response_with_content(body);
        let ranges = response
            .get_body_keypaths_ranges(&["items[0]", "items[1]"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_fields_from_array_elements_extraction() {
        let users = RangedValue::Array {
            range: 10..100,
            value: vec![
                RangedValue::Object {
                    range: 11..50,
                    value: {
                        let mut map = std::collections::HashMap::new();
                        map.insert(
                            "name".to_string(),
                            RangedValue::String {
                                range: 20..25,
                                value: "Alice".to_string(),
                            },
                        );
                        map.insert(
                            "email".to_string(),
                            RangedValue::String {
                                range: 35..50,
                                value: "alice@example.com".to_string(),
                            },
                        );
                        map
                    },
                },
                RangedValue::Object {
                    range: 51..90,
                    value: {
                        let mut map = std::collections::HashMap::new();
                        map.insert(
                            "name".to_string(),
                            RangedValue::String {
                                range: 60..63,
                                value: "Bob".to_string(),
                            },
                        );
                        map.insert(
                            "email".to_string(),
                            RangedValue::String {
                                range: 73..86,
                                value: "bob@example.com".to_string(),
                            },
                        );
                        map
                    },
                },
            ],
        };

        let body = RangedValue::Object {
            range: 0..110,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert("users".to_string(), users);
                map
            },
        };

        let request = create_test_request_with_content(body);
        let ranges = request
            .get_body_keypaths_ranges(&["users[0].name", "users[1].email"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_nested_arrays_extraction() {
        let matrix = RangedValue::Array {
            range: 10..80,
            value: vec![
                RangedValue::Array {
                    range: 11..30,
                    value: vec![
                        RangedValue::Number {
                            range: 12..13,
                            value: 1.0,
                        },
                        RangedValue::Number {
                            range: 14..15,
                            value: 2.0,
                        },
                    ],
                },
                RangedValue::Array {
                    range: 31..70,
                    value: vec![
                        RangedValue::Number {
                            range: 32..33,
                            value: 3.0,
                        },
                        RangedValue::Number {
                            range: 34..35,
                            value: 4.0,
                        },
                        RangedValue::Number {
                            range: 36..37,
                            value: 5.0,
                        },
                    ],
                },
            ],
        };

        let body = RangedValue::Object {
            range: 0..90,
            value: {
                let mut map = std::collections::HashMap::new();
                map.insert("matrix".to_string(), matrix);
                map
            },
        };

        let response = create_test_response_with_content(body);
        let ranges = response
            .get_body_keypaths_ranges(&["matrix[0][0]", "matrix[1][2]"])
            .unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 12..13);
        assert_eq!(ranges[1], 36..37);
    }
}
