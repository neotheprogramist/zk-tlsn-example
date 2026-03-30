use circuit_prover::prover::{CircuitProof, prove_circuit};
use circuits::blake::{HashValue, blake, blake_qm31};
use circuits::context::Context;
use circuits::ivalue::qm31_from_u32s;
use circuits::ops::{eq, guess, output};
use serde::{Deserialize, Serialize};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::ExtendedStarkProof;
use stwo::core::vcs::blake2_hash::reduce_to_m31;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher;

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

    output(&mut ctx, tlsn_hash0);
    output(&mut ctx, tlsn_hash1);

    ctx.finalize_guessed_vars();
    ctx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStwoProof {
    pub stark_proof: ExtendedStarkProof<Blake2sM31MerkleHasher>,
    pub pcs_config: PcsConfig,
    /// `CircuitClaim.log_sizes` - component trace sizes.
    pub claim_log_sizes: Vec<u32>,
    /// `CircuitClaim.output_values` - public outputs of the circuit (committed_hash as 2 x QM31).
    pub claim_output_values: Vec<QM31>,
    /// `CircuitInteractionClaim.claimed_sums` - logup interaction sums.
    pub interaction_claim_sums: Vec<QM31>,
    pub interaction_pow_nonce: u64,
    pub channel_salt: u32,
}

impl AttestationStwoProof {
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

fn circuit_proof_to_attestation(cp: CircuitProof) -> Result<AttestationStwoProof, String> {
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
    let circuit_proof = prove_circuit(&mut ctx);
    circuit_proof_to_attestation(circuit_proof)
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
