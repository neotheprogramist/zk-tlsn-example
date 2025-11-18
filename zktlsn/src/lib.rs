mod error;
mod prover;
mod verifier;

#[cfg(test)]
mod tests;

pub use error::{Result, ZkTlsnError};
pub use prover::{Proof, generate_proof};
pub use verifier::verify_proof;
