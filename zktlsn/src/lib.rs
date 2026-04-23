mod aggregate;
mod cli;
mod commitment;
mod error;
mod padding;
mod proof;
mod prover;
mod recursive;
mod ticket;
mod verifier;

use std::path::Path;

pub use aggregate::{RecursiveSettlement, aggregate_attestations};
pub use commitment::{BoundCommitment, bind_commitments_to_keys};
pub use error::{Result, ZkTlsnError};
pub use padding::PaddingConfig;
pub use proof::{
    extract_committed_hash_from_proof, extract_transfer_fields_from_proof,
    verify_proof_against_hash,
};
pub use prover::{
    AttestationProof, KeccakProof, NoirProverInputs, Proof, prove_attestation,
    prove_attestation_from_inputs,
};
pub use recursive::{
    RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit, RecursiveState, VkArtifacts,
    build_recursive_prover_toml, compile_all_packages, derive_circuit_vk,
    generate_honk_solidity_verifier, prove_keccak_circuit, prove_noir_recursive_circuit,
    prove_null_circuit, state_from_public_inputs,
};
pub use ticket::{SignedTransferTicket, TicketSigner, VERIFIER_TICKET_PRIVATE_KEY_ENV};
pub use verifier::validate_generated_solidity_verifier;

pub fn ensure_cli_toolchain() -> Result<()> {
    cli::ensure_cli_toolchain()
}

pub fn compile_attestation_package() -> Result<()> {
    recursive::compile_attestation_package()
}

pub fn cleanup_cli_outputs() -> Result<()> {
    cli::cleanup_cli_outputs()
}

pub(crate) fn repo_root() -> &'static Path {
    // PROOF: CARGO_MANIFEST_DIR is set by Cargo at compile time and always
    // points to this crate's Cargo.toml directory, which by workspace layout
    // is a child of the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zktlsn crate lives under the workspace root")
}
