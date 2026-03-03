mod prove;
mod types;
mod verify;

pub use prove::prove_commitment;
pub use types::{CommitmentStatement0, ProofData, VerifyError};
pub use verify::verify_proof;
