#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

pub mod withdraw;
pub mod offchain_merkle;
pub mod poseidon_hash;
// pub mod blake3;
// pub mod offer_circuit;
// pub mod offer_spend_circuit;
// pub mod privacy_pool;
// pub mod withdraw_circuit;
// mod proof;

// pub use blake3::scheduler::compute_commitment_hash;
// pub use offer_circuit::{
//     OfferCreateInputs, OfferCreateProof, OfferCreatePublicInputs, prove_offer_create,
//     verify_offer_create,
// };
// pub use offer_spend_circuit::{
//     OfferAcceptInputs, OfferAcceptProof, OfferAcceptPublicInputs,
//     prove_offer_accept, verify_offer_accept,
// };
// pub use withdraw_circuit::{
//     WithdrawInputs, WithdrawProof, WithdrawPublicInputs, prove_withdraw, verify_withdraw,
// };
// pub use privacy_pool::merkle_membership;
// pub use privacy_pool::{
//     onchain,
//     onchain::{build_offer_onchain_verification_input, build_cancel_offer_calldata,
//         build_onchain_verification_input, build_verify_calldata, build_create_offer_calldata, build_offer_accept_onchain_verification_input,
//         send_withdraw_with_proof_tx, simulate_withdraw_with_proof_call, verify_onchain_call,
//     },
//     poseidon_chain, poseidon_hash, relations, scheduler,
// };
// pub use proof::{CommitmentStatement0, ProofData, VerifyError, prove_commitment, verify_proof};