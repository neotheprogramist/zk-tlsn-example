use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaddingConfig {
    pub commitment_length: usize,
}

impl PaddingConfig {
    #[must_use]
    pub const fn new(commitment_length: usize) -> Self {
        Self { commitment_length }
    }
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self::new(10)
    }
}
