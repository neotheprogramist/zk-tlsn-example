use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone, Default)]
pub struct PathStack {
    segments: Vec<PathSegment>,
}

impl PathStack {
    pub fn push(&mut self, segment: PathSegment) {
        self.segments.push(segment);
    }

    pub fn pop(&mut self) -> Option<PathSegment> {
        self.segments.pop()
    }
}

impl fmt::Display for PathStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for segment in &self.segments {
            match segment {
                PathSegment::Key(k) => write!(f, ".{k}")?,
                PathSegment::Index(i) => write!(f, "[{i}]")?,
            }
        }
        Ok(())
    }
}
