pub mod cli;
pub mod prove;
pub mod recursive;

pub use prove::{
    AttestationProof, KeccakProof, NoirProverInputs, Proof, ProofTransferFields,
    extract_committed_hash_from_proof, extract_transfer_fields_from_proof, prove_attestation,
    prove_attestation_from_inputs,
};
pub use recursive::{
    PaddingConfig, RECURSIVE_PUBLIC_INPUTS, RecursiveCircuit, RecursiveSettlement, RecursiveState,
    VkArtifacts, aggregate_attestations, build_recursive_prover_toml, compile_all_packages,
    derive_circuit_vk, generate_honk_solidity_verifier, prove_keccak_circuit,
    prove_noir_recursive_circuit, prove_null_circuit, state_from_public_inputs,
    validate_generated_solidity_verifier,
};
