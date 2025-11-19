use std::{collections::HashMap, ops::Range};

use crate::types::{Body, Header};

pub trait HttpMessage {
    fn headers(&self) -> &HashMap<String, Vec<Header>>;

    fn chunk_size(&self) -> &Range<usize>;

    fn body(&self) -> &HashMap<String, Body>;

    fn get_header(&self, name: &str) -> Option<&Vec<Header>> {
        self.headers().get(&name.to_lowercase())
    }

    fn get_first_header(&self, name: &str) -> Option<&Header> {
        self.get_header(name)?.first()
    }

    fn get_body_value(&self, path: &str) -> Option<&Body> {
        self.body().get(path)
    }
}
