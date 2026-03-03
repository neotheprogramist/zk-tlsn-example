#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

pub mod blake3;
mod proof;

pub use blake3::scheduler::compute_commitment_hash;
pub use proof::{
    prove_commitment, verify_proof, CommitmentStatement0, ProofData, VerifyError,
};
