use circuit_air::components::prelude::Zero;
use circuit_air::{CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements};
use circuit_air::components::{CircuitComponents, N_COMPONENTS};
use circuit_air::{lookup_sum, statement::INTERACTION_POW_BITS};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, prove_circuit_assignment};
use circuits::context::{Context, Var};
use circuits::ivalue::qm31_from_u32s;
use circuits::ops::{eq, guess, output};
use circuits::poseidon2::{RATE, poseidon2_sponge_circuit};
use shared::{AMOUNT_WIDTH, ATTESTATION_LEN, TX_ID_WIDTH, USER_ID_WIDTH, FiatTransferAttestation, encode_transfer_attestation};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::proof::ExtendedStarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};

fn att_bytes(tx_id: u64, to_user_id: u64, amount: u64) -> [u8; ATTESTATION_LEN] {
    encode_transfer_attestation(FiatTransferAttestation::new(tx_id, to_user_id, amount))
        .expect("fields fit encoding")
        .as_bytes()
        .try_into()
        .expect("attestation must be ATTESTATION_LEN bytes")
}

fn hash_bytes_to_qm31(bytes: &[u8; 32]) -> [QM31; 8] {
    std::array::from_fn(|i| {
        let word = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        qm31_from_u32s(word, 0, 0, 0)
    })
}

fn parse_decimal_circuit(ctx: &mut Context<QM31>, digit_vars: &[Var]) -> Var {
    let ascii_zero = ctx.constant(qm31_from_u32s(48, 0, 0, 0));
    let ten = ctx.constant(qm31_from_u32s(10, 0, 0, 0));
    let mut result = ctx.zero();
    for &digit_var in digit_vars {
        let digit = circuits::eval!(ctx, (digit_var) - (ascii_zero));
        result = circuits::eval!(ctx, ((result) * (ten)) + (digit));
    }
    result
}

fn build_attestation_circuit(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
    commitment: [QM31; 8],
    tx_id: u64,
    to_user_id: u64,
    amount: u64,
) -> Context<QM31> {
    let mut ctx = Context::<QM31>::default();

    let att_vars: Vec<Var> = attestation
        .iter()
        .map(|&b| guess(&mut ctx, qm31_from_u32s(b as u32, 0, 0, 0)))
        .collect();
    let blinder_vars: Vec<Var> = blinder
        .iter()
        .map(|&b| guess(&mut ctx, qm31_from_u32s(b as u32, 0, 0, 0)))
        .collect();

    let parsed_tx_id = parse_decimal_circuit(&mut ctx, &att_vars[..TX_ID_WIDTH]);
    let parsed_to_user_id = parse_decimal_circuit(&mut ctx, &att_vars[TX_ID_WIDTH..TX_ID_WIDTH + USER_ID_WIDTH]);
    let parsed_amount = parse_decimal_circuit(&mut ctx, &att_vars[TX_ID_WIDTH + USER_ID_WIDTH..TX_ID_WIDTH + USER_ID_WIDTH + AMOUNT_WIDTH]);
    let tx_id_const = ctx.constant(qm31_from_u32s(tx_id as u32, 0, 0, 0));
    let to_user_id_const = ctx.constant(qm31_from_u32s(to_user_id as u32, 0, 0, 0));
    let amount_const = ctx.constant(qm31_from_u32s(amount as u32, 0, 0, 0));
    eq(&mut ctx, parsed_tx_id, tx_id_const);
    eq(&mut ctx, parsed_to_user_id, to_user_id_const);
    eq(&mut ctx, parsed_amount, amount_const);

    let mut blocks: Vec<[Var; RATE]> = att_vars
        .chunks(RATE)
        .map(|chunk| std::array::from_fn(|i| chunk[i]))
        .collect();
    blocks.extend(blinder_vars.chunks(RATE).map(|chunk| std::array::from_fn(|i| chunk[i])));
    let state = poseidon2_sponge_circuit(&mut ctx, &blocks);

    let commitment_vars: [Var; 8] = std::array::from_fn(|i| {
        let cv = ctx.constant(commitment[i]);
        eq(&mut ctx, state[i], cv);
        cv
    });
    for lane in &state[8..] {
        ctx.mark_as_maybe_unused(lane);
    }

    for cv in &commitment_vars {
        output(&mut ctx, *cv);
    }
    output(&mut ctx, tx_id_const);
    output(&mut ctx, to_user_id_const);
    output(&mut ctx, amount_const);

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
}

impl AttestationStwoProof {
    /// Returns (tx_id, to_user_id, amount) from public outputs.
    pub fn transfer_fields(&self) -> Option<(u64, u64, u64)> {
        if self.claim_output_values.len() < 11 {
            return None;
        }
        let tx_id = self.claim_output_values[8].0.0.0 as u64;
        let to_user_id = self.claim_output_values[9].0.0.0 as u64;
        let amount = self.claim_output_values[10].0.0.0 as u64;
        Some((tx_id, to_user_id, amount))
    }

    /// Returns the 8 Poseidon2 sponge state elements as public commitment.
    pub fn commitment(&self) -> Option<[QM31; 8]> {
        if self.claim_output_values.len() < 8 {
            return None;
        }
        Some(std::array::from_fn(|i| self.claim_output_values[i]))
    }

    /// Returns the commitment as 32 bytes (4 LE bytes per M31 limb, 8 limbs).
    pub fn commitment_bytes(&self) -> Option<[u8; 32]> {
        let elems = self.commitment()?;
        let mut out = [0u8; 32];
        for (i, qm31) in elems.iter().enumerate() {
            let limb = qm31.0.0.0;
            out[i * 4..i * 4 + 4].copy_from_slice(&limb.to_le_bytes());
        }
        Some(out)
    }
}

fn circuit_proof_to_attestation(
    cp: CircuitProof,
    output_addresses: Vec<usize>,
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
    })
}

pub fn prove_attestation(
    attestation: &[u8; ATTESTATION_LEN],
    blinder: &[u8; 16],
    attestation_committed_hash: &[u8; 32],
    tx_id: u64,
    to_user_id: u64,
    amount: u64,
) -> Result<AttestationStwoProof, String> {
    let commitment = hash_bytes_to_qm31(attestation_committed_hash);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ctx = build_attestation_circuit(attestation, blinder, commitment, tx_id, to_user_id, amount);
        let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut ctx);
        let circuit_proof = prove_circuit_assignment(
            ctx.values(),
            &preprocessed,
            &BaseColumnPool::new(),
        );
        circuit_proof_to_attestation(circuit_proof, preprocessed.params.output_addresses)
    }))
    .map_err(|_| "circuit constraint violated: witness does not satisfy constraints".to_string())?
}

pub fn verify_attestation(proof: &AttestationStwoProof) -> Result<(), String> {
    // Dummy context to recover circuit topology for verification; witnesses don't matter.
    let dummy_att = att_bytes(1, 2, 3);
    let dummy_blinder = [0u8; 16];
    let dummy_commitment = [QM31::zero(); 8];
    let mut ctx = build_attestation_circuit(&dummy_att, &dummy_blinder, dummy_commitment, 1, 2, 3);
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
    ) != QM31::zero()
    {
        return Err("lookup sum check failed".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poseidon_hash(attestation: &[u8; ATTESTATION_LEN], blinder: &[u8; 16]) -> [u8; 32] {
        let mut h = poseidon_m31::PoseidonHasher::new();
        h.update(attestation);
        h.update(blinder);
        h.finalize()
    }

    #[test]
    fn test_attestation_bytes_format() {
        let att = att_bytes(1, 3, 25);
        assert_eq!(std::str::from_utf8(&att).unwrap(), "00000000010000000003000000000025");
    }

    #[test]
    fn test_different_attestation_gives_different_commitment() {
        let blinder = [1u8; 16];
        assert_ne!(
            poseidon_hash(&att_bytes(1, 3, 25), &blinder),
            poseidon_hash(&att_bytes(999, 3, 25), &blinder),
        );
    }

    #[test]
    fn test_build_attestation_circuit() {
        let attestation = att_bytes(1, 3, 25);
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let committed_hash = poseidon_hash(&attestation, &blinder);
        let ctx = build_attestation_circuit(&attestation, &blinder, hash_bytes_to_qm31(&committed_hash), 1, 3, 25);
        ctx.check_vars_used();
    }

    #[test]
    fn test_prove_and_verify_attestation() {
        let attestation = att_bytes(1, 3, 25);
        let blinder = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let committed_hash = poseidon_hash(&attestation, &blinder);
        let proof = prove_attestation(&attestation, &blinder, &committed_hash, 1, 3, 25)
            .expect("proving should succeed");
        verify_attestation(&proof).expect("verification should succeed");
        let (tx_id, to_user_id, amount) = proof.transfer_fields().expect("transfer fields present");
        assert_eq!((tx_id, to_user_id, amount), (1, 3, 25));
        assert!(proof.commitment_bytes().is_some());
    }
}
