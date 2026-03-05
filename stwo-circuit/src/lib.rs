#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

pub mod blake3;
pub mod combined_circuit;
pub mod offchain_merkle;
pub mod privacy_pool;
mod proof;

pub use blake3::scheduler::compute_commitment_hash;
pub use combined_circuit::{WithdrawInputs, WithdrawProof, prove_withdraw, verify_withdraw};
// Backward-compatible exports: keep old paths working after moving modules to privacy_pool/.
pub use privacy_pool::merkle_membership;
pub use privacy_pool::{
    onchain,
    onchain::{
        build_onchain_verification_input, build_verify_calldata, send_withdraw_with_proof_tx,
        simulate_withdraw_with_proof_call, verify_onchain_call,
    },
    poseidon_chain, poseidon_hash, relations, scheduler,
};
pub use proof::{CommitmentStatement0, ProofData, VerifyError, prove_commitment, verify_proof};
