use std::{collections::HashMap, ops::Range};

#[derive(Debug, Clone, Default)]
pub struct RangedHeader {
    pub range: Range<usize>,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum RangedValue {
    Null,
    Bool {
        range: Range<usize>,
        value: bool,
    },
    Number {
        range: Range<usize>,
        value: f64,
    },
    String {
        range: Range<usize>,
        value: String,
    },
    Array {
        range: Range<usize>,
        value: Vec<RangedValue>,
    },
    Object {
        range: Range<usize>,
        value: HashMap<String, RangedValue>,
    },
}

impl Default for RangedValue {
    fn default() -> Self {
        RangedValue::Object {
            range: Default::default(),
            value: Default::default(),
        }
    }
}

impl RangedValue {
    pub fn get_range(&self) -> Range<usize> {
        match self {
            RangedValue::Null => 0..0,
            RangedValue::Bool { range, .. }
            | RangedValue::Number { range, .. }
            | RangedValue::String { range, .. }
            | RangedValue::Array { range, .. }
            | RangedValue::Object { range, .. } => range.clone(),
        }
    }
}
