mod aggregate;
pub mod cli;
mod error;
mod prover;
pub mod recursive;

use std::path::Path;

pub use aggregate::{RecursiveSettlement, aggregate_attestations};
pub use error::{Result, ZkTlsnError};
pub use prover::{
    AttestationProof, KeccakProof, NoirProverInputs, Proof, extract_committed_hash_from_proof,
    extract_transfer_fields_from_proof, prove_attestation, prove_attestation_from_inputs,
};
pub use recursive::{
    PaddingConfig, RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit, RecursiveState, VkArtifacts,
    build_recursive_prover_toml, compile_all_packages, derive_circuit_vk,
    generate_honk_solidity_verifier, prove_keccak_circuit, prove_noir_recursive_circuit,
    prove_null_circuit, state_from_public_inputs, validate_generated_solidity_verifier,
};

pub(crate) fn repo_root() -> &'static Path {
    // PROOF: CARGO_MANIFEST_DIR is set by Cargo at compile time and always
    // points to this crate's Cargo.toml directory, which by workspace layout
    // is a child of the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zktlsn crate lives under the workspace root")
}
