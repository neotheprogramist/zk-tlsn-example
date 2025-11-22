//! Fixed-length commitments to hide value length in zero-knowledge proofs.
//!
//! Commitments always cover a fixed number of bytes regardless of actual value length,
//! preventing information leakage (e.g., "100" vs "9999999").

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
