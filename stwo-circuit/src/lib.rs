#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

pub mod blake3;
pub mod offer_circuit;
pub mod offchain_merkle;
pub mod privacy_pool;
pub mod withdraw_circuit;
mod proof;

pub use blake3::scheduler::compute_commitment_hash;
pub use offer_circuit::{
    OfferSpendInputs, OfferSpendProof, prove_offer_withdraw, verify_offer_withdraw,
};
pub use withdraw_circuit::{WithdrawInputs, WithdrawProof, prove_withdraw, verify_withdraw};
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
