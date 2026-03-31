use circuit_air::components::prelude::Zero;
use circuit_air::{CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements};
use circuit_air::components::{CircuitComponents, N_COMPONENTS};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_air::{lookup_sum, statement::INTERACTION_POW_BITS};
use circuit_prover::prover::{BaseColumnPool, CircuitProof, prove_circuit_assignment};
use circuits::blake::{HashValue, blake, blake_qm31};
use circuits::context::Context;
use circuits::ivalue::qm31_from_u32s;
use circuits::ops::{eq, guess, output};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::proof::ExtendedStarkProof;
use stwo::core::vcs::blake2_hash::reduce_to_m31;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};

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

pub fn compute_attestation_commitment(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
) -> HashValue<QM31> {
    let att0 = pack_bytes16(attestation[0..16].try_into().unwrap());
    let att1 = pack_bytes16(attestation[16..32].try_into().unwrap());
    let blinder_qm31 = pack_bytes16(blinder);
    blake_qm31(&[att0, att1, blinder_qm31], 48)
}

pub fn hash_value_to_bytes(hash: HashValue<QM31>) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, qm31) in [hash.0, hash.1].iter().enumerate() {
        let coords = [qm31.0.0.0, qm31.0.1.0, qm31.1.0.0, qm31.1.1.0];
        for (j, &coord) in coords.iter().enumerate() {
            out[i * 16 + j * 4..i * 16 + j * 4 + 4].copy_from_slice(&coord.to_le_bytes());
        }
    }
    out
}

pub fn bytes_to_hash_value(raw: [u8; 32]) -> HashValue<QM31> {
    let normalized = reduce_to_m31(raw);
    let qm31_0 = pack_bytes16(normalized[0..16].try_into().unwrap());
    let qm31_1 = pack_bytes16(normalized[16..32].try_into().unwrap());
    HashValue(qm31_0, qm31_1)
}

pub fn normalize_digest_for_stwo(raw_digest: [u8; 32]) -> [u8; 32] {
    reduce_to_m31(raw_digest)
}


pub fn build_attestation_circuit(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
    tlsn_hash: HashValue<QM31>,
    tx_id: u64,
    to_user_id: u64,
    amount: u64,
) -> Context<QM31> {
    let mut ctx = Context::<QM31>::default();

    let att0_var = guess(&mut ctx, pack_bytes16(attestation[0..16].try_into().unwrap()));
    let att1_var = guess(&mut ctx, pack_bytes16(attestation[16..32].try_into().unwrap()));
    let blinder_var = guess(&mut ctx, pack_bytes16(blinder));

    let tlsn_hash0 = ctx.constant(tlsn_hash.0);
    let tlsn_hash1 = ctx.constant(tlsn_hash.1);

    let expected_att = attestation_bytes(tx_id, to_user_id, amount);
    let expected_att0 = ctx.constant(pack_bytes16(expected_att[0..16].try_into().unwrap()));
    let expected_att1 = ctx.constant(pack_bytes16(expected_att[16..32].try_into().unwrap()));
    eq(&mut ctx, att0_var, expected_att0);
    eq(&mut ctx, att1_var, expected_att1);

    let hash_out = blake(&mut ctx, &[att0_var, att1_var, blinder_var], 48);
    eq(&mut ctx, hash_out.0, tlsn_hash0);
    eq(&mut ctx, hash_out.1, tlsn_hash1);

    let tx_id_var = ctx.constant(qm31_from_u32s(tx_id as u32, 0, 0, 0));
    let to_user_id_var = ctx.constant(qm31_from_u32s(to_user_id as u32, 0, 0, 0));
    let amount_var = ctx.constant(qm31_from_u32s(amount as u32, 0, 0, 0));

    output(&mut ctx, tlsn_hash0);
    output(&mut ctx, tlsn_hash1);
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
    pub fn transfer_fields(&self) -> Option<(u64, u64, u64)> {
        if self.claim_output_values.len() < 5 {
            return None;
        }
        let tx_id = self.claim_output_values[2].0.0.0 as u64;
        let to_user_id = self.claim_output_values[3].0.0.0 as u64;
        let amount = self.claim_output_values[4].0.0.0 as u64;
        Some((tx_id, to_user_id, amount))
    }

    pub fn committed_hash(&self) -> Option<[u8; 32]> {
        if self.claim_output_values.len() < 2 {
            return None;
        }
        let mut hash = [0u8; 32];
        for (i, qm31) in self.claim_output_values[..2].iter().enumerate() {
            let coords = [qm31.0.0.0, qm31.0.1.0, qm31.1.0.0, qm31.1.1.0];
            for (j, &coord) in coords.iter().enumerate() {
                let bytes = coord.to_le_bytes();
                hash[i * 16 + j * 4..i * 16 + j * 4 + 4].copy_from_slice(&bytes);
            }
        }
        Some(hash)
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
    tlsn_hash: &[u8; 32],
    tx_id: u64,
    to_user_id: u64,
    amount: u64,
) -> Result<AttestationStwoProof, String> {
    let tlsn_hash_qm31 = bytes_to_hash_value(*tlsn_hash);
    let mut ctx =
        build_attestation_circuit(attestation, blinder, tlsn_hash_qm31, tx_id, to_user_id, amount);
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

pub fn verify_attestation(
    proof: &AttestationStwoProof
) -> Result<(), String> {
    let dummy_attestation = attestation_bytes(1, 2, 3);
    let dummy_hash = HashValue(qm31_from_u32s(1, 2, 3, 4), qm31_from_u32s(5, 6, 7, 8));
    let mut ctx = build_attestation_circuit(
        &dummy_attestation,
        &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        dummy_hash,
        1u64,
        2u64,
        3u64,
    );

    let preprocessed_circuit = PreprocessedCircuit::preprocess_circuit(&mut ctx);

    let log_sizes: [u32; N_COMPONENTS] = proof.claim_log_sizes.as_slice().try_into().map_err(|_| format!(
        "claim_log_sizes length mismatch: expected {N_COMPONENTS}, got {}",
        proof.claim_log_sizes.len()
    ))?;

    let claim = CircuitClaim {
        log_sizes,
        output_values: proof.claim_output_values.clone()
    };

    let claimed_sums: [QM31; N_COMPONENTS] = proof.interaction_claim_sums
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
        dummy_components.components().iter().map(|c| c.trace_log_degree_bounds())
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
        &components.components().iter().map(|c| c.as_ref()).collect::<Vec<&dyn Component>>(),
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
    ) != QM31::zero() {
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
        let s = std::str::from_utf8(&att).unwrap();
        assert_eq!(s, "00000000010000000003000000000025");
    }

    #[test]
    fn test_build_attestation_circuit() {
        let tx_id = 1u64;
        let to_user_id = 3u64;
        let amount = 25u64;
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let attestation = attestation_bytes(tx_id, to_user_id, amount);

        let expected_hash = compute_attestation_commitment(&attestation, &blinder);
        let ctx = build_attestation_circuit(
            &attestation,
            &blinder,
            expected_hash,
            tx_id,
            to_user_id,
            amount,
        );

        ctx.check_vars_used();
    }

    #[test]
    fn test_prove_attestation() {
        use blake2::{Blake2s256, Digest};
        
        let tx_id = 1u64;
        let to_user_id = 3u64;
        let amount = 25u64;
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let attestation = attestation_bytes(tx_id, to_user_id, amount);

        let mut hasher = Blake2s256::new();
        hasher.update(&attestation);
        hasher.update(&blinder);
        let tlsn_hash: [u8; 32] = hasher.finalize().into();

        let proof = prove_attestation(&attestation, &blinder, &tlsn_hash, tx_id, to_user_id, amount)
            .expect("proving should succeed");

        let proof_hash = proof.committed_hash().expect("proof should have output values");

        let normalized = normalize_digest_for_stwo(tlsn_hash);
        assert_eq!(proof_hash, normalized);
    }

    #[test]
    fn test_verify_attestation() {
        use blake2::{Blake2s256, Digest};

        let tx_id = 1u64;
        let to_user_id = 3u64;
        let amount = 25u64;
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let attestation = attestation_bytes(tx_id, to_user_id, amount);

        let mut hasher = Blake2s256::new();
        hasher.update(&attestation);
        hasher.update(&blinder);
        let tlsn_hash: [u8; 32] = hasher.finalize().into();

        let proof = prove_attestation(&attestation, &blinder, &tlsn_hash, tx_id, to_user_id, amount)
            .expect("proving should succeed");

        verify_attestation(&proof).expect("verification should succeed");
    }

    #[test]
    fn test_wrong_attestation_produces_different_hash() {
        let tx_id = 1u64;
        let to_user_id = 3u64;
        let amount = 25u64;
        let blinder = [1u8; 16];

        let correct_att = attestation_bytes(tx_id, to_user_id, amount);
        let wrong_att = attestation_bytes(999, to_user_id, amount);

        let hash_correct = compute_attestation_commitment(&correct_att, &blinder);
        let hash_wrong = compute_attestation_commitment(&wrong_att, &blinder);

        assert_ne!(hash_correct.0, hash_wrong.0);
    }
}
