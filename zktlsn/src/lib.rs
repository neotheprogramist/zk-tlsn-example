mod cli;
mod commitment;
mod error;
mod padding;
mod proof;
mod prover;
mod recursive;
mod ticket;
mod verifier;

#[cfg(test)]
mod test_fixtures;

#[cfg(test)]
mod tests;

use std::path::Path;

pub use commitment::{BoundCommitment, bind_commitments_to_keys};
pub use error::{Result, ZkTlsnError};
pub use padding::PaddingConfig;
pub use proof::{
    ProofTransferFields, extract_committed_hash_from_proof, extract_transfer_fields_from_proof,
    verify_proof, verify_proof_against_hash,
};
pub use prover::{
    KeccakProof, NoirProverInputs, Proof, SettlementBundle, derive_noir_prover_inputs,
    generate_settlement_bundle, generate_settlement_bundle_from_inputs,
};
pub use recursive::{
    HONK_FIELD_BYTES, INNER_PUBLIC_INPUTS, NULL_PUBLIC_INPUTS, RECURSIVE_PUBLIC_INPUTS,
    RecursiveCircuit, RecursiveState, VkArtifacts, build_recursive_prover_toml,
    compile_all_packages, derive_circuit_vk, generate_honk_solidity_verifier,
    hex_field_words_to_bytes, parse_hex_field_word, prove_keccak_circuit,
    prove_noir_recursive_circuit, prove_null_circuit, state_from_public_inputs,
};
pub use ticket::{
    DEFAULT_VERIFIER_TICKET_PRIVATE_KEY, SignedTransferTicket, TicketSigner,
    VERIFIER_TICKET_PRIVATE_KEY_ENV, ticket_message_hash,
};
pub use verifier::{
    validate_generated_solidity_verifier, validate_generated_solidity_verifier_for_bytecode,
};

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
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zktlsn crate should live under the workspace root")
}
