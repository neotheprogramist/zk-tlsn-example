use base64::Engine;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::offchain_merkle::poseidon_hash_pair;
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

use crate::{error::ApiError, types::{VerifyAndSignRequest, VerifyAndSignRecursiveWithdrawRequest, VerifyAndSignRecursiveCreateOfferRequest}};

// Output indices — must match recursive_withdraw_circuit.rs constants.
const IDX_ROOT_ACC: usize = 0;
const IDX_NULLIFIER_ACC: usize = 1;
const IDX_TOKEN: usize = 2;
const IDX_AMOUNT: usize = 3;
const IDX_RECIPIENT: usize = 5;
const WITHDRAW_CIRCUIT_ROOT_U32: [u32; 8] =
    [652536158, 1858539233, 59812728, 107606911, 121169370, 567731177, 498092224, 1678070508];
const OFFER_CIRCUIT_ROOT_U32: [u32; 8] =
    [2083006622, 875350036, 949412405, 1403257640, 1687447398, 1160659095, 1153139438, 1349329321];

const OFFER_SPEND_CANCEL_CIRCUIT_ROOT_U32: [u32; 8] =
    [228289986, 724834124, 320566596, 1181551808, 1139858737, 1093925691, 977744636, 212433008];

// Terminal offer circuit: verifies full recursive accumulated proof + proves offerCommitment in ZK.
// Step2 == stable (terminal stabilises at N=2, one step earlier than the accumulator).
const OFFER_TERMINAL_STEP1_ROOT_U32: [u32; 8] =
    [2123831596, 774154872, 215040919, 45785260, 2140798896, 1452535023, 922618969, 1961052800];
const OFFER_TERMINAL_STABLE_ROOT_U32: [u32; 8] =
    [626675481, 2013871859, 1212401755, 198642368, 2081990364, 1953051901, 873756461, 1192898319];

const RECURSIVE_STEP1_ROOT_U32: [u32; 8] =
    [1754113036, 1826477655, 1206977738, 950444227, 2075168426, 1808668797, 2085858017, 954426740];
const RECURSIVE_STEP2_ROOT_U32: [u32; 8] =
    [1155964987, 933233646, 528970039, 1582259721, 1555438329, 144756265, 1155259030, 1008049394];
const RECURSIVE_STABLE_ROOT_U32: [u32; 8] =
    [1541694134, 290880061, 1909421654, 822925969, 734728419, 1288299412, 886742156, 972296609];


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
        root_from_u32s(RECURSIVE_STEP1_ROOT_U32),
        root_from_u32s(RECURSIVE_STEP2_ROOT_U32),
        root_from_u32s(RECURSIVE_STABLE_ROOT_U32),
        root_from_u32s(OFFER_TERMINAL_STEP1_ROOT_U32),
        root_from_u32s(OFFER_TERMINAL_STABLE_ROOT_U32),
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

pub struct VerifiedRecursiveWithdraw {
    pub proof_hash_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    pub nullifiers: Vec<u32>,
    pub merkle_roots: Vec<u32>,
    pub token: u32,
    pub total_amount: u32,
    pub recipient: u32,
}

/// Verifies a recursive batch-withdrawal proof and validates the nullifier/root lists.
///
/// Steps:
///   1. STARK proof verification (preprocessed root must be in the recursive allowlist).
///   2. Reconstruct nullifier_acc = poseidon(poseidon(...0, n0...), nk) and assert it
///      matches claim_output_values[IDX_NULLIFIER_ACC].
///   3. Reconstruct root_acc = poseidon(poseidon(...0, r0...), rk) and assert it
///      matches claim_output_values[IDX_ROOT_ACC].
///   4. Build a claim that commits to the full nullifier list, root list, token,
///      amount, and recipient — so the contract can verify the same signature.
pub fn verify_recursive_withdraw(
    req: &VerifyAndSignRecursiveWithdrawRequest,
) -> Result<VerifiedRecursiveWithdraw, ApiError> {
    let as_verify_req = VerifyAndSignRequest {
        proof_id: req.proof_id.clone(),
        pcs_config_b64: req.pcs_config_b64.clone(),
        stark_proof_b64: req.stark_proof_b64.clone(),
        channel_salt: req.channel_salt,
        interaction_pow_nonce: req.interaction_pow_nonce,
        claim_log_sizes: req.claim_log_sizes.clone(),
        claim_output_values: req.claim_output_values.clone(),
        interaction_claimed_sums: req.interaction_claimed_sums.clone(),
        stage1_trace_log_sizes: req.stage1_trace_log_sizes.clone(),
        stage2_trace_log_sizes: req.stage2_trace_log_sizes.clone(),
        preprocessed_trace_log_sizes: req.preprocessed_trace_log_sizes.clone(),
        preprocessed_column_ids: req.preprocessed_column_ids.clone(),
        output_addresses: req.output_addresses.clone(),
        n_blake_gates: req.n_blake_gates,
    };

    let verified = verify_raw_stwo_proof(&as_verify_req)?;

    if req.nullifiers.is_empty() {
        return Err(ApiError::InvalidInput("nullifiers must not be empty".to_string()));
    }
    if req.merkle_roots.is_empty() {
        return Err(ApiError::InvalidInput("merkle_roots must not be empty".to_string()));
    }
    if req.nullifiers.len() != req.merkle_roots.len() {
        return Err(ApiError::InvalidInput(
            "nullifiers and merkle_roots must have the same length".to_string(),
        ));
    }

    let outputs = &req.claim_output_values;
    if outputs.len() <= IDX_RECIPIENT {
        return Err(ApiError::InvalidInput(format!(
            "claim_output_values must have at least {} entries",
            IDX_RECIPIENT + 1
        )));
    }

    // Reconstruct nullifier_acc off-chain and compare to circuit output.
    let expected_nullifier_acc = req.nullifiers.iter().fold(
        BaseField::from_u32_unchecked(0),
        |acc, &n| poseidon_hash_pair(acc, BaseField::from_u32_unchecked(n)),
    );
    let circuit_nullifier_acc = outputs[IDX_NULLIFIER_ACC][0];
    if expected_nullifier_acc.0 != circuit_nullifier_acc {
        return Err(ApiError::Verification(format!(
            "nullifier_acc mismatch: recomputed {}, circuit output {}",
            expected_nullifier_acc.0, circuit_nullifier_acc
        )));
    }

    // Reconstruct root_acc off-chain and compare to circuit output.
    let expected_root_acc = req.merkle_roots.iter().fold(
        BaseField::from_u32_unchecked(0),
        |acc, &r| poseidon_hash_pair(acc, BaseField::from_u32_unchecked(r)),
    );
    let circuit_root_acc = outputs[IDX_ROOT_ACC][0];
    if expected_root_acc.0 != circuit_root_acc {
        return Err(ApiError::Verification(format!(
            "root_acc mismatch: recomputed {}, circuit output {}",
            expected_root_acc.0, circuit_root_acc
        )));
    }

    let token = outputs[IDX_TOKEN][0];
    let total_amount = outputs[IDX_AMOUNT][0];
    let recipient = outputs[IDX_RECIPIENT][0];

    // Compute claim hash committing to the full signed payload.
    // Layout: prefix | n_nullifiers(4) | nullifiers... | n_roots(4) | roots... | token(4) | amount(4) | recipient(4)
    let proof_hash_bytes = hex::decode(&verified.proof_hash_hex)
        .map_err(|e| ApiError::Internal(format!("hex decode proof_hash: {e}")))?;

    let mut claim_bytes = Vec::new();
    claim_bytes.extend_from_slice(b"trusted-stwo-recursive-withdraw-v1");
    claim_bytes.extend_from_slice(&proof_hash_bytes);
    claim_bytes.extend_from_slice(&(req.nullifiers.len() as u32).to_be_bytes());
    for &n in &req.nullifiers {
        claim_bytes.extend_from_slice(&n.to_be_bytes());
    }
    claim_bytes.extend_from_slice(&(req.merkle_roots.len() as u32).to_be_bytes());
    for &r in &req.merkle_roots {
        claim_bytes.extend_from_slice(&r.to_be_bytes());
    }
    claim_bytes.extend_from_slice(&token.to_be_bytes());
    claim_bytes.extend_from_slice(&total_amount.to_be_bytes());
    claim_bytes.extend_from_slice(&recipient.to_be_bytes());
    let claim_hash = keccak256(&claim_bytes);

    let mut message_bytes = Vec::new();
    message_bytes.extend_from_slice(b"trusted-stwo-message-v1");
    message_bytes.extend_from_slice(&claim_hash);
    let message_hash = keccak256(&message_bytes);

    Ok(VerifiedRecursiveWithdraw {
        proof_hash_hex: verified.proof_hash_hex,
        claim_hash_hex: hex::encode(claim_hash),
        message_hash_hex: hex::encode(message_hash),
        nullifiers: req.nullifiers.clone(),
        merkle_roots: req.merkle_roots.clone(),
        token,
        total_amount,
        recipient,
    })
}

pub struct VerifiedRecursiveCreateOffer {
    pub proof_hash_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    pub nullifiers: Vec<u32>,
    pub merkle_roots: Vec<u32>,
    pub token: u32,
    pub total_amount: u32,
    /// offerCommitment is output[4] of the terminal circuit — proven in ZK, not server-computed.
    pub offer_commitment: u32,
    /// offerRefundSnHash is output[6] of the terminal circuit — proven in ZK.
    pub offer_refund_sn_hash: u32,
    pub secret_hash: u32,
}

/// Verifies a recursive batch-offer terminal proof.
///
/// The terminal circuit proves offerCommitment as output[4] — server reads it directly
/// from the public outputs without computing it from private inputs.
/// Server still reconstructs nullifier_acc and root_acc to validate the provided lists.
pub fn verify_recursive_create_offer(
    req: &VerifyAndSignRecursiveCreateOfferRequest,
) -> Result<VerifiedRecursiveCreateOffer, ApiError> {
    let as_verify_req = VerifyAndSignRequest {
        proof_id: req.proof_id.clone(),
        pcs_config_b64: req.pcs_config_b64.clone(),
        stark_proof_b64: req.stark_proof_b64.clone(),
        channel_salt: req.channel_salt,
        interaction_pow_nonce: req.interaction_pow_nonce,
        claim_log_sizes: req.claim_log_sizes.clone(),
        claim_output_values: req.claim_output_values.clone(),
        interaction_claimed_sums: req.interaction_claimed_sums.clone(),
        stage1_trace_log_sizes: req.stage1_trace_log_sizes.clone(),
        stage2_trace_log_sizes: req.stage2_trace_log_sizes.clone(),
        preprocessed_trace_log_sizes: req.preprocessed_trace_log_sizes.clone(),
        preprocessed_column_ids: req.preprocessed_column_ids.clone(),
        output_addresses: req.output_addresses.clone(),
        n_blake_gates: req.n_blake_gates,
    };

    let verified = verify_raw_stwo_proof(&as_verify_req)?;

    if req.nullifiers.is_empty() {
        return Err(ApiError::InvalidInput("nullifiers must not be empty".to_string()));
    }
    if req.merkle_roots.is_empty() {
        return Err(ApiError::InvalidInput("merkle_roots must not be empty".to_string()));
    }
    if req.nullifiers.len() != req.merkle_roots.len() {
        return Err(ApiError::InvalidInput(
            "nullifiers and merkle_roots must have the same length".to_string(),
        ));
    }

    // Terminal circuit outputs: [root_acc, nullifier_acc, token, total_amount, offerCommitment, 0, offerRefundSnHash]
    let outputs = &req.claim_output_values;
    if outputs.len() < 7 {
        return Err(ApiError::InvalidInput(
            "claim_output_values must have at least 7 entries (terminal circuit outputs)".to_string(),
        ));
    }

    let expected_nullifier_acc = req.nullifiers.iter().fold(
        BaseField::from_u32_unchecked(0),
        |acc, &n| poseidon_hash_pair(acc, BaseField::from_u32_unchecked(n)),
    );
    let circuit_nullifier_acc = outputs[1][0];
    if expected_nullifier_acc.0 != circuit_nullifier_acc {
        return Err(ApiError::Verification(format!(
            "nullifier_acc mismatch: recomputed {}, circuit output {}",
            expected_nullifier_acc.0, circuit_nullifier_acc
        )));
    }

    let expected_root_acc = req.merkle_roots.iter().fold(
        BaseField::from_u32_unchecked(0),
        |acc, &r| poseidon_hash_pair(acc, BaseField::from_u32_unchecked(r)),
    );
    let circuit_root_acc = outputs[0][0];
    if expected_root_acc.0 != circuit_root_acc {
        return Err(ApiError::Verification(format!(
            "root_acc mismatch: recomputed {}, circuit output {}",
            expected_root_acc.0, circuit_root_acc
        )));
    }

    let token = outputs[2][0];
    let total_amount = outputs[3][0];
    // Read offerCommitment and offerRefundSnHash directly from ZK-proven circuit outputs.
    let offer_commitment = outputs[4][0];
    let offer_refund_sn_hash = outputs[6][0];

    let proof_hash_bytes = hex::decode(&verified.proof_hash_hex)
        .map_err(|e| ApiError::Internal(format!("hex decode proof_hash: {e}")))?;

    // Claim binds: proof identity, nullifier/root lists, all 7 circuit outputs, offer identifier.
    let mut claim_bytes = Vec::new();
    claim_bytes.extend_from_slice(b"trusted-stwo-recursive-create-offer-v1");
    claim_bytes.extend_from_slice(&proof_hash_bytes);
    claim_bytes.extend_from_slice(&(req.nullifiers.len() as u32).to_be_bytes());
    for &n in &req.nullifiers {
        claim_bytes.extend_from_slice(&n.to_be_bytes());
    }
    claim_bytes.extend_from_slice(&(req.merkle_roots.len() as u32).to_be_bytes());
    for &r in &req.merkle_roots {
        claim_bytes.extend_from_slice(&r.to_be_bytes());
    }
    claim_bytes.extend_from_slice(&token.to_be_bytes());
    claim_bytes.extend_from_slice(&total_amount.to_be_bytes());
    claim_bytes.extend_from_slice(&offer_commitment.to_be_bytes());
    claim_bytes.extend_from_slice(&offer_refund_sn_hash.to_be_bytes());
    claim_bytes.extend_from_slice(&req.secret_hash.to_be_bytes());
    let claim_hash = keccak256(&claim_bytes);

    let mut message_bytes = Vec::new();
    message_bytes.extend_from_slice(b"trusted-stwo-message-v1");
    message_bytes.extend_from_slice(&claim_hash);
    let message_hash = keccak256(&message_bytes);

    Ok(VerifiedRecursiveCreateOffer {
        proof_hash_hex: verified.proof_hash_hex,
        claim_hash_hex: hex::encode(claim_hash),
        message_hash_hex: hex::encode(message_hash),
        nullifiers: req.nullifiers.clone(),
        merkle_roots: req.merkle_roots.clone(),
        token,
        total_amount,
        offer_commitment,
        offer_refund_sn_hash,
        secret_hash: req.secret_hash,
    })
}
