use circuit_air::components::prelude::Zero;
use circuit_air::{CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements};
use circuit_air::components::{CircuitComponents, N_COMPONENTS};
use circuit_air::{lookup_sum, statement::INTERACTION_POW_BITS};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, prove_circuit_assignment};
use circuits::blake::blake;
use circuits::context::Context;
use circuits::ivalue::qm31_from_u32s;
use circuits::ops::{eq, guess, output};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::proof::ExtendedStarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};

use crate::poseidon2::poseidon2_hash_two;

pub const ATTESTATION_LEN: usize = 32;
const TX_ID_WIDTH: usize = 10;
const USER_ID_WIDTH: usize = 10;
const AMOUNT_WIDTH: usize = 12;

pub fn attestation_bytes(tx_id: u64, to_user_id: u64, amount: u64) -> [u8; ATTESTATION_LEN] {
    let s = format!(
        "{:0>width_tx$}{:0>width_user$}{:0>width_amount$}",
        tx_id,
        to_user_id,
        amount,
        width_tx = TX_ID_WIDTH,
        width_user = USER_ID_WIDTH,
        width_amount = AMOUNT_WIDTH,
    );
    s.as_bytes().try_into().expect("attestation must be 32 bytes")
}

fn pack_bytes16(bytes: &[u8; 16]) -> QM31 {
    qm31_from_u32s(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
    )
}

/// Compute Poseidon2 commitment natively (same path as inside circuit).
/// h1 = P2(att[0..16], att[16..32]), h2 = P2(h1, blinder) → single QM31.
pub fn compute_attestation_commitment(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
) -> QM31 {
    let mut ctx = Context::<QM31>::default();
    let att0 = ctx.constant(pack_bytes16(attestation[0..16].try_into().unwrap()));
    let att1 = ctx.constant(pack_bytes16(attestation[16..32].try_into().unwrap()));
    let b = ctx.constant(pack_bytes16(blinder));
    let h1 = poseidon2_hash_two(&mut ctx, att0, att1);
    let h2 = poseidon2_hash_two(&mut ctx, h1, b);
    ctx.get(h2)
}

pub fn pad_attestation_blake_rows(ctx: &mut Context<QM31>) {
    const N_LANES: usize = 16;
    let zero = ctx.zero();

    let n_constants = ctx.constants().len();
    let n_hash_compressions = (n_constants + 3) / 4;

    let mut extra = 0usize;
    loop {
        let total_compressions = n_hash_compressions + extra;
        let rounded = ((total_compressions + N_LANES - 1) / N_LANES).max(1) * N_LANES;
        let pad_count = rounded - total_compressions;
        let total_gates = 1 + extra + pad_count;
        if total_gates >= N_LANES {
            break;
        }
        extra += 1;
    }

    for _ in 0..extra {
        let out = blake(ctx, &[zero], 1);
        ctx.mark_as_maybe_unused(&out.0);
        ctx.mark_as_maybe_unused(&out.1);
    }
}

pub fn build_attestation_circuit(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
    commitment: QM31,
    tx_id: u64,
    to_user_id: u64,
    amount: u64,
) -> Context<QM31> {
    let mut ctx = Context::<QM31>::default();

    // Private witnesses: the two halves of attestation and the blinder.
    let att0_var = guess(&mut ctx, pack_bytes16(attestation[0..16].try_into().unwrap()));
    let att1_var = guess(&mut ctx, pack_bytes16(attestation[16..32].try_into().unwrap()));
    let blinder_var = guess(&mut ctx, pack_bytes16(blinder));

    // Constrain attestation fields match public tx data.
    let expected_att = attestation_bytes(tx_id, to_user_id, amount);
    let expected_att0 = ctx.constant(pack_bytes16(expected_att[0..16].try_into().unwrap()));
    let expected_att1 = ctx.constant(pack_bytes16(expected_att[16..32].try_into().unwrap()));
    eq(&mut ctx, att0_var, expected_att0);
    eq(&mut ctx, att1_var, expected_att1);

    // Poseidon2: h1 = P2(att0, att1), h2 = P2(h1, blinder).
    let h1 = poseidon2_hash_two(&mut ctx, att0_var, att1_var);
    let h2 = poseidon2_hash_two(&mut ctx, h1, blinder_var);

    // Constrain Poseidon2 hash matches public commitment.
    let commitment_var = ctx.constant(commitment);
    eq(&mut ctx, h2, commitment_var);

    // Public outputs: commitment, tx_id, to_user_id, amount.
    let tx_id_var = ctx.constant(qm31_from_u32s(tx_id as u32, 0, 0, 0));
    let to_user_id_var = ctx.constant(qm31_from_u32s(to_user_id as u32, 0, 0, 0));
    let amount_var = ctx.constant(qm31_from_u32s(amount as u32, 0, 0, 0));
    output(&mut ctx, commitment_var);
    output(&mut ctx, tx_id_var);
    output(&mut ctx, to_user_id_var);
    output(&mut ctx, amount_var);

    ctx.finalize_guessed_vars();
    ctx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStwoProof {
    pub stark_proof: ExtendedStarkProof<Blake2sM31MerkleHasher>,
    pub pcs_config: PcsConfig,
    pub claim_log_sizes: Vec<u32>,
    pub claim_output_values: Vec<QM31>,
    pub interaction_claim_sums: Vec<QM31>,
    pub interaction_pow_nonce: u64,
    pub channel_salt: u32,
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
}

impl AttestationStwoProof {
    /// Returns (tx_id, to_user_id, amount) from public outputs.
    pub fn transfer_fields(&self) -> Option<(u64, u64, u64)> {
        if self.claim_output_values.len() < 4 {
            return None;
        }
        let tx_id = self.claim_output_values[1].0.0.0 as u64;
        let to_user_id = self.claim_output_values[2].0.0.0 as u64;
        let amount = self.claim_output_values[3].0.0.0 as u64;
        Some((tx_id, to_user_id, amount))
    }

    /// Returns the Poseidon2 commitment QM31 from public outputs.
    pub fn commitment(&self) -> Option<QM31> {
        self.claim_output_values.first().copied()
    }
}

fn circuit_proof_to_attestation(
    cp: CircuitProof,
    output_addresses: Vec<usize>,
    n_blake_gates: usize,
) -> Result<AttestationStwoProof, String> {
    let stark_proof = cp
        .stark_proof
        .map_err(|e| format!("proving failed: {e:?}"))?;
    Ok(AttestationStwoProof {
        stark_proof,
        pcs_config: cp.pcs_config,
        claim_log_sizes: cp.claim.log_sizes.to_vec(),
        claim_output_values: cp.claim.output_values,
        interaction_claim_sums: cp.interaction_claim.claimed_sums.to_vec(),
        interaction_pow_nonce: cp.interaction_pow_nonce,
        channel_salt: cp.channel_salt,
        output_addresses,
        n_blake_gates,
    })
}

pub fn prove_attestation(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
    tx_id: u64,
    to_user_id: u64,
    amount: u64,
) -> Result<AttestationStwoProof, String> {
    let commitment = compute_attestation_commitment(attestation, blinder);
    let mut ctx = build_attestation_circuit(attestation, blinder, commitment, tx_id, to_user_id, amount);
    pad_attestation_blake_rows(&mut ctx);
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut ctx);
    let output_addresses = preprocessed.params.output_addresses.clone();
    let n_blake_gates = preprocessed.params.n_blake_gates;
    let circuit_proof = prove_circuit_assignment(
        ctx.values(),
        &preprocessed,
        &BaseColumnPool::new(),
    );
    circuit_proof_to_attestation(circuit_proof, output_addresses, n_blake_gates)
}

pub fn verify_attestation(proof: &AttestationStwoProof) -> Result<(), String> {
    // Dummy context with the same circuit structure (witnesses don't matter for verification).
    let dummy_att = attestation_bytes(1, 2, 3);
    let dummy_blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let dummy_commitment = compute_attestation_commitment(&dummy_att, &dummy_blinder);
    let mut ctx = build_attestation_circuit(&dummy_att, &dummy_blinder, dummy_commitment, 1, 2, 3);
    pad_attestation_blake_rows(&mut ctx);
    let preprocessed_circuit = PreprocessedCircuit::preprocess_circuit(&mut ctx);

    let log_sizes: [u32; N_COMPONENTS] = proof
        .claim_log_sizes
        .as_slice()
        .try_into()
        .map_err(|_| format!(
            "claim_log_sizes length mismatch: expected {N_COMPONENTS}, got {}",
            proof.claim_log_sizes.len()
        ))?;
    let claim = CircuitClaim {
        log_sizes,
        output_values: proof.claim_output_values.clone(),
    };

    let claimed_sums: [QM31; N_COMPONENTS] = proof
        .interaction_claim_sums
        .as_slice()
        .try_into()
        .map_err(|_| format!(
            "interaction_claim_sums length mismatch: expected {N_COMPONENTS}, got {}",
            proof.interaction_claim_sums.len()
        ))?;
    let interaction_claim = CircuitInteractionClaim { claimed_sums };

    let dummy_ie = CircuitInteractionElements::draw(&mut Blake2sM31Channel::default());
    let dummy_components = CircuitComponents::new(
        &claim,
        &dummy_ie,
        &interaction_claim,
        &preprocessed_circuit.preprocessed_trace.ids(),
    );
    let sizes = TreeVec::concat_cols(
        dummy_components.components().iter().map(|c| c.trace_log_degree_bounds()),
    );

    let channel = &mut Blake2sM31Channel::default();
    channel.mix_felts(&[proof.channel_salt.into()]);
    proof.pcs_config.mix_into(channel);
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(proof.pcs_config);

    commitment_scheme.commit(
        proof.stark_proof.proof.commitments[0],
        &preprocessed_circuit.preprocessed_trace.log_sizes(),
        channel,
    );
    claim.mix_into(channel);
    commitment_scheme.commit(proof.stark_proof.proof.commitments[1], &sizes[1], channel);
    channel.verify_pow_nonce(INTERACTION_POW_BITS, proof.interaction_pow_nonce);
    channel.mix_u64(proof.interaction_pow_nonce);
    let interaction_elements = CircuitInteractionElements::draw(channel);

    let components = CircuitComponents::new(
        &claim,
        &interaction_elements,
        &interaction_claim,
        &preprocessed_circuit.preprocessed_trace.ids(),
    );

    interaction_claim.mix_into(channel);
    commitment_scheme.commit(proof.stark_proof.proof.commitments[2], &sizes[2], channel);

    stwo::core::verifier::verify_ex(
        &components
            .components()
            .iter()
            .map(|c| c.as_ref())
            .collect::<Vec<&dyn Component>>(),
        channel,
        commitment_scheme,
        proof.stark_proof.proof.clone(),
        true,
    )
    .map_err(|e| format!("STARK verification failed: {e:?}"))?;

    if lookup_sum(
        &claim,
        &interaction_claim,
        &interaction_elements,
        &proof.output_addresses,
        proof.n_blake_gates,
    ) != QM31::zero()
    {
        return Err("lookup sum check failed".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_bytes_format() {
        let att = attestation_bytes(1, 3, 25);
        assert_eq!(std::str::from_utf8(&att).unwrap(), "00000000010000000003000000000025");
    }

    #[test]
    fn test_commitment_deterministic() {
        let att = attestation_bytes(1, 3, 25);
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let c1 = compute_attestation_commitment(&att, &blinder);
        let c2 = compute_attestation_commitment(&att, &blinder);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_wrong_attestation_different_commitment() {
        let blinder = [1u8; 16];
        let h1 = compute_attestation_commitment(&attestation_bytes(1, 3, 25), &blinder);
        let h2 = compute_attestation_commitment(&attestation_bytes(999, 3, 25), &blinder);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_build_attestation_circuit() {
        let attestation = attestation_bytes(1, 3, 25);
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let commitment = compute_attestation_commitment(&attestation, &blinder);
        let ctx = build_attestation_circuit(&attestation, &blinder, commitment, 1, 3, 25);
        ctx.check_vars_used();
    }

    #[test]
    fn test_prove_and_verify_attestation() {
        let attestation = attestation_bytes(1, 3, 25);
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let proof = prove_attestation(&attestation, &blinder, 1, 3, 25)
            .expect("proving should succeed");
        verify_attestation(&proof).expect("verification should succeed");
    }

       #[test]
       fn test_prove_and_stark_verify_attestation_context() {
           let attestation = attestation_bytes(1, 3, 25);
           let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
           let commitment = compute_attestation_commitment(&attestation, &blinder);
           let mut context = build_attestation_circuit(&attestation, &blinder, commitment, 1, 3, 25);
           pad_attestation_blake_rows(&mut context);
           context.validate_circuit();

           let preprocessed_circuit = PreprocessedCircuit::preprocess_circuit(&mut context);
           let circuit_proof = prove_circuit_assignment(
               context.values(),
               &preprocessed_circuit,
               &BaseColumnPool::new(),
           );

           assert!(circuit_proof.stark_proof.is_ok(), "Got error: {}", circuit_proof.stark_proof.err().unwrap());
           verify_attestation(&circuit_proof_to_attestation(
               circuit_proof,
               preprocessed_circuit.params.output_addresses.clone(),
               preprocessed_circuit.params.n_blake_gates,
           ).expect("conversion should succeed")).expect("verification should succeed");
       }
}
