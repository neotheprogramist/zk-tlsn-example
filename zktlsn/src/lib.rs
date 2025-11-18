mod error;
mod prover;
mod verifier;

#[cfg(test)]
mod tests;

pub use error::{Result, ZkTlsnError};
pub use prover::{generate_proof, Proof};
pub use verifier::verify_proof;
