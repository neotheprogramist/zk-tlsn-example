#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

mod commitment;
mod error;
mod padding;
mod prover;
mod verifier;

#[cfg(test)]
mod tests;

pub use commitment::{BoundCommitment, bind_commitments_to_keys};
pub use error::{Result, ZkTlsnError};
pub use padding::PaddingConfig;
pub use prover::{Proof, generate_proof};
pub use verifier::verify_proof;
