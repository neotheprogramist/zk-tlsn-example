use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("invalid attestation length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("missing attestation segment: {0}")]
    MissingSegment(&'static str),

    #[error("invalid attestation segment {label}")]
    InvalidSegment {
        label: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("attestation segment {label} value {value} exceeds {width}-digit limit")]
    SegmentTooWide {
        label: &'static str,
        value: u64,
        width: u32,
    },
}
