mod error;
mod prover;

#[cfg(test)]
mod tests;

pub use error::{Result, ZkTlsnError};
pub use prover::{Proof, generate_proof};
