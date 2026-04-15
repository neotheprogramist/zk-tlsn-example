use base64::Engine;
use circuit_air::{
    CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements, lookup_sum,
    components::{CircuitComponents, N_COMPONENTS},
    components::prelude::PreProcessedColumnId,
    statement::INTERACTION_POW_BITS,
};
use circuits::{blake::HashValue, ivalue::qm31_from_u32s};
use stwo::core::{
    air::Component, channel::{Blake2sM31Channel, Channel}, fields::qm31::QM31, pcs::{CommitmentSchemeVerifier, PcsConfig}, proof::ExtendedStarkProof, vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher}
};

use crate::{error::ApiError, types::VerifyAndSignRequest};
const WITHDRAW_CIRCUIT_ROOT_U32: [u32; 8] =
    [652536158, 1858539233, 59812728, 107606911, 121169370, 567731177, 498092224, 1678070508];
const OFFER_CIRCUIT_ROOT_U32: [u32; 8] =
    [2083006622, 875350036, 949412405, 1403257640, 1687447398, 1160659095, 1153139438, 1349329321];

const OFFER_SPEND_CANCEL_CIRCUIT_ROOT_U32: [u32; 8] =
    [228289986, 724834124, 320566596, 1181551808, 1139858737, 1093925691, 977744636, 212433008];


pub struct VerifiedProof {
    pub proof_hash_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
}

fn root_from_u32s(words: [u32; 8]) -> HashValue<QM31> {
    HashValue(
        qm31_from_u32s(words[0], words[1], words[2], words[3]),
        qm31_from_u32s(words[4], words[5], words[6], words[7]),
    )
}

pub fn verify_raw_stwo_proof(req: &VerifyAndSignRequest) -> Result<VerifiedProof, ApiError> {
    let allowed_root_list = vec![
        root_from_u32s(WITHDRAW_CIRCUIT_ROOT_U32),
        root_from_u32s(OFFER_CIRCUIT_ROOT_U32),
        root_from_u32s(OFFER_SPEND_CANCEL_CIRCUIT_ROOT_U32),
    ];
    println!("Verifying proof with proof_id: {}", req.proof_id);
    if req.claim_log_sizes.len() != N_COMPONENTS {
        return Err(ApiError::InvalidInput(format!(
            "claim_log_sizes length must be {N_COMPONENTS}"
        )));
    }
    if req.interaction_claimed_sums.len() != N_COMPONENTS {
        return Err(ApiError::InvalidInput(format!(
            "interaction_claimed_sums length must be {N_COMPONENTS}"
        )));
    }
    let pcs_config: PcsConfig = decode_b64_bincode(&req.pcs_config_b64)?;
    let stark_proof_bytes = decode_b64(&req.stark_proof_b64)?;
    let stark_proof: ExtendedStarkProof<Blake2sM31MerkleHasher> =
        bincode::deserialize(&stark_proof_bytes)
            .map_err(|e| ApiError::Decode(format!("bincode decode error: {e}")))?;

    let claim = CircuitClaim {
        log_sizes: req
            .claim_log_sizes
            .clone()
            .try_into()
            .map_err(|_| ApiError::InvalidInput("invalid claim_log_sizes array length".to_string()))?,
        output_values: req
            .claim_output_values
            .iter()
            .map(|v| qm31_from_u32s(v[0], v[1], v[2], v[3]))
            .collect(),
    };

    let interaction_claim = CircuitInteractionClaim {
        claimed_sums: req
            .interaction_claimed_sums
            .iter()
            .map(|v| qm31_from_u32s(v[0], v[1], v[2], v[3]))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| ApiError::InvalidInput("invalid interaction_claimed_sums array length".to_string()))?,
    };

    let preprocessed_ids = req
        .preprocessed_column_ids
        .iter()
        .map(|id| PreProcessedColumnId { id: id.clone() })
        .collect::<Vec<_>>();

    let (proof_hash_hex, claim_hash_hex, message_hash_hex) =
        compute_signature_hashes(req, &stark_proof_bytes)?;

    let verifier_channel = &mut Blake2sM31Channel::default();
    verifier_channel.mix_felts(&[req.channel_salt.into()]);
    pcs_config.mix_into(verifier_channel);

    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

    commitment_scheme.commit(
        stark_proof.proof.commitments[0],
        &req.preprocessed_trace_log_sizes,
        verifier_channel,
    );

    claim.mix_into(verifier_channel);

    if req.stage1_trace_log_sizes.is_empty() {
        return Err(ApiError::InvalidInput(
            "stage1_trace_log_sizes must not be empty".to_string(),
        ));
    }
    if req.stage2_trace_log_sizes.is_empty() {
        return Err(ApiError::InvalidInput(
            "stage2_trace_log_sizes must not be empty".to_string(),
        ));
    }

    commitment_scheme.commit(
        stark_proof.proof.commitments[1],
        &req.stage1_trace_log_sizes,
        verifier_channel,
    );
    verifier_channel.verify_pow_nonce(INTERACTION_POW_BITS, req.interaction_pow_nonce);
    verifier_channel.mix_u64(req.interaction_pow_nonce);

    let interaction_elements = CircuitInteractionElements::draw(verifier_channel);
    interaction_claim.mix_into(verifier_channel);

    let circuit_components = CircuitComponents::new(
        &claim,
        &interaction_elements,
        &interaction_claim,
        preprocessed_ids.as_slice(),
    );
    let components = circuit_components.components();

    commitment_scheme.commit(
        stark_proof.proof.commitments[2],
        &req.stage2_trace_log_sizes,
        verifier_channel,
    );
    let preprocessed_root: HashValue<QM31> = stark_proof.proof.commitments[0].into();
    println!("Proof preprocessed root: {:?}", preprocessed_root);

    let mut selector_values = vec![qm31_from_u32s(0, 0, 0, 0); allowed_root_list.len()];

    let idx = allowed_root_list
            .iter()
            .position(|r| *r == preprocessed_root)
            .ok_or_else(|| ApiError::Verification("proof preprocessed root not in allowlist".to_string()))?;
    selector_values[idx] = qm31_from_u32s(1, 0, 0, 0);

    stwo::core::verifier::verify_ex(
        &components
            .iter()
            .map(|c| c.as_ref())
            .collect::<Vec<&dyn Component>>(),
        verifier_channel,
        commitment_scheme,
        stark_proof.proof,
        true,
    )
    .map_err(|e| ApiError::Verification(format!("stark verification failed: {e:?}")))?;

    let sum = lookup_sum(
        &claim,
        &interaction_claim,
        &interaction_elements,
        &req.output_addresses,
        req.n_blake_gates,
    );

    if sum != qm31_from_u32s(0, 0, 0, 0) {
        return Err(ApiError::Verification(
            "lookup_sum must equal zero".to_string(),
        ));
    }

    Ok(VerifiedProof {
        proof_hash_hex,
        claim_hash_hex,
        message_hash_hex,
    })
}

fn decode_b64_bincode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, ApiError> {
    let bytes = decode_b64(value)?;

    bincode::deserialize::<T>(&bytes)
        .map_err(|e| ApiError::Decode(format!("bincode decode error: {e}")))
}

fn decode_b64(value: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| ApiError::Decode(format!("base64 decode error: {e}")))
}

fn compute_signature_hashes(
    req: &VerifyAndSignRequest,
    stark_proof_bytes: &[u8],
) -> Result<(String, String, String), ApiError> {
    let proof_hash = keccak256(stark_proof_bytes);

    if req.claim_output_values.len() < 6 {
        return Err(ApiError::InvalidInput(
            "claim_output_values must contain at least 6 outputs".to_string(),
        ));
    }

    let scalar_prefix_count = req
        .claim_output_values
        .iter()
        .take_while(|limbs| limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0)
        .count();

    let signed_output_count = if scalar_prefix_count >= 8 {
        8
    } else if scalar_prefix_count >= 7 {
        7
    } else {
        6
    };
    if scalar_prefix_count < signed_output_count {
        return Err(ApiError::InvalidInput(format!(
            "claim_output_values must contain at least {signed_output_count} scalar outputs"
        )));
    }

    // Compact execution hash used by on-chain execution methods.
    let mut claim_bytes = Vec::with_capacity(24 + signed_output_count * 4);
    claim_bytes.extend_from_slice(b"trusted-stwo-claim-v1");
    for (idx, limbs) in req
        .claim_output_values
        .iter()
        .take(signed_output_count)
        .enumerate()
    {
        if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
            return Err(ApiError::InvalidInput(format!(
                "claim_output_values[{idx}] must be scalar QM31 (imaginary limbs must be zero)"
            )));
        }
        claim_bytes.extend_from_slice(&limbs[0].to_be_bytes());
    }
    let claim_hash = keccak256(&claim_bytes);

    // Final message hash signed by trusted server.
    let mut message_bytes = Vec::with_capacity(32 + 24);
    message_bytes.extend_from_slice(b"trusted-stwo-message-v1");
    message_bytes.extend_from_slice(&claim_hash);
    let message_hash = keccak256(&message_bytes);

    Ok((
        hex::encode(&proof_hash),
        hex::encode(&claim_hash),
        hex::encode(&message_hash),
    ))
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(bytes);
    k.finalize(&mut out);
    out
}
