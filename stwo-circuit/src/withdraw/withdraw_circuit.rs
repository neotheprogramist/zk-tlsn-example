#[cfg(test)]
use circuit_prover::prover::prove_circuit;
#[cfg(test)]
use circuit_common::preprocessed::PreprocessedCircuit;
#[cfg(test)]
use circuit_prover::prover::{BaseColumnPool, prove_circuit_assignment};
use circuits::{
    context::Context,
    ops::{cond_flip, eq, guess, mul, output, sub},
};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::QM31;
#[cfg(test)]
use stwo::prover::backend::simd::SimdBackend;
use circuits::poseidon2;

use crate::offchain_merkle::{OffchainMerkleTree, poseidon_hash_pair};

#[derive(Debug, Clone)]
pub struct WithdrawMerkleWitness {
    // deposit data
    pub expected_root: QM31,
    pub secret: QM31,
    pub nullifier: QM31,
    pub commitment_amount: QM31,
    pub token: QM31,
    pub siblings: Vec<QM31>,
    /// LSB-first bits (bit 0 = lowest tree level)
    pub index_bits_lsb: Vec<QM31>,

    // withdraw amount (public)
    pub amount: QM31,

    // refund data
    pub refund_secret: QM31,
    pub refund_nullifier: QM31,
    pub refund_amount: QM31,
    pub refund_commitment_hash: QM31,

    // recipient is public in Noir circuit (currently not used in constraints)
    pub recipient: QM31,
}

fn m31_to_qm31(value: BaseField) -> QM31 {
    QM31::from(value.0)
}

pub fn build_withdraw_merkle_context( witness: &WithdrawMerkleWitness) -> Context<QM31> {
    assert_eq!(
        witness.siblings.len(),
        witness.index_bits_lsb.len(),
        "siblings and index_bits_lsb must have the same length"
    );
    let mut context = Context::<QM31>::default();
    let one = context.one();
    let zero = context.zero();

    let root = guess(&mut context, witness.expected_root);
    let secret = guess(&mut context, witness.secret);
    let nullifier = guess(&mut context, witness.nullifier);
    let commitment_amount = guess(&mut context, witness.commitment_amount);
    let token = guess(&mut context, witness.token);
    let amount = guess(&mut context, witness.amount);
    let refund_secret = guess(&mut context, witness.refund_secret);
    let refund_nullifier = guess(&mut context, witness.refund_nullifier);
    let refund_amount = guess(&mut context, witness.refund_amount);
    let refund_commitment_hash = guess(&mut context, witness.refund_commitment_hash);
    let recipient = guess(&mut context, witness.recipient);

    // commitment_amount == amount + refund_amount
    let neg_refund_amount = sub(&mut context, zero, refund_amount);
    let amount_plus_refund = sub(&mut context, amount, neg_refund_amount);
    eq(&mut context, commitment_amount, amount_plus_refund);

    // leaf = H(H(H(secret, nullifier), commitment_amount), token)
    let computed_secret_nullifier_hash = poseidon2::poseidon2_hash_two(&mut context, secret, nullifier);
    let secret_nullifier_amount_hash =
        poseidon2::poseidon2_hash_two(&mut context, computed_secret_nullifier_hash, commitment_amount);
    let leaf = poseidon2::poseidon2_hash_two(&mut context, secret_nullifier_amount_hash, token);

    // verify membership(root, leaf, index_bits_lsb, hashpath)
    let mut current = leaf;

    for (&bit_value, &sibling_value) in witness
        .index_bits_lsb
        .iter()
        .zip(witness.siblings.iter())
    {
        let bit = guess(&mut context, bit_value);
        let sibling = guess(&mut context, sibling_value);

        // Enforce bit in {0, 1}.
        let bit_minus_one = sub(&mut context, bit, one);
        let bit_is_binary = mul(&mut context, bit, bit_minus_one);
        eq(&mut context, bit_is_binary, zero);

        // bit=0 => (current, sibling), bit=1 => (sibling, current)
        let (left, right) = cond_flip(&mut context, bit, current, sibling);
        current = poseidon2::poseidon2_hash_two(&mut context, left, right);
    }

    eq(&mut context, current, root);

    // refund_commitment_hash == H(H(H(refund_secret, refund_nullifier), refund_amount), token)
    let computed_secret_nullifier_hash_refund =
        poseidon2::poseidon2_hash_two(&mut context, refund_secret, refund_nullifier);
    let secret_nullifier_amount_hash_final = poseidon2::poseidon2_hash_two(
        &mut context,
        computed_secret_nullifier_hash_refund,
        refund_amount,
    );
    let refund_computed_commitment =
        poseidon2::poseidon2_hash_two(&mut context, secret_nullifier_amount_hash_final, token);
    eq(&mut context, refund_commitment_hash, refund_computed_commitment);

    output(&mut context, root);
    output(&mut context, nullifier);
    output(&mut context, token);
    output(&mut context, amount);
    output(&mut context, refund_commitment_hash);
    output(&mut context, recipient);

    context
}

fn compute_commitment_offchain(
    secret: BaseField,
    nullifier: BaseField,
    amount: BaseField,
    token: BaseField,
) -> BaseField {
    let sn = poseidon_hash_pair(secret, nullifier);
    let sna = poseidon_hash_pair(sn, amount);
    poseidon_hash_pair(sna, token)
}

pub fn build_withdraw_merkle_context_from_offchain_tree(
    tree: &OffchainMerkleTree,
    secret: BaseField,
    nullifier: BaseField,
    commitment_amount: BaseField,
    token: BaseField,
    amount: BaseField,
    refund_secret: BaseField,
    refund_nullifier: BaseField,
    refund_amount: BaseField,
    recipient: BaseField,
) -> Result<Context<QM31>, String> {
    let leaf = compute_commitment_offchain(secret, nullifier, commitment_amount, token);

    let index = tree
        .find_leaf_index(leaf)
        .ok_or_else(|| format!("Leaf {} not found in offchain tree", leaf.0))?;

    let (siblings, is_right_bits) = tree.path(index);

    let refund_commitment_hash =
        compute_commitment_offchain(refund_secret, refund_nullifier, refund_amount, token);

    let witness = WithdrawMerkleWitness {
        expected_root: m31_to_qm31(tree.root()),
        secret: m31_to_qm31(secret),
        nullifier: m31_to_qm31(nullifier),
        commitment_amount: m31_to_qm31(commitment_amount),
        token: m31_to_qm31(token),
        siblings: siblings.into_iter().map(m31_to_qm31).collect(),
        index_bits_lsb: is_right_bits
            .into_iter()
            .map(|bit| QM31::from(if bit { 1u32 } else { 0u32 }))
            .collect(),
        amount: m31_to_qm31(amount),
        refund_secret: m31_to_qm31(refund_secret),
        refund_nullifier: m31_to_qm31(refund_nullifier),
        refund_amount: m31_to_qm31(refund_amount),
        refund_commitment_hash: m31_to_qm31(refund_commitment_hash),
        recipient: m31_to_qm31(recipient),
    };

    Ok(build_withdraw_merkle_context(&witness))
}

#[test]
fn test_withdraw_merkle_circuit() {
    let secret = BaseField::from_u32_unchecked(11);
    let nullifier = BaseField::from_u32_unchecked(333);
    let token = BaseField::from_u32_unchecked(42);
    let amount = BaseField::from_u32_unchecked(100);
    let refund_amount = BaseField::from_u32_unchecked(20);
    let commitment_amount = amount + refund_amount;
    let refund_secret = BaseField::from_u32_unchecked(55);
    let refund_nullifier = BaseField::from_u32_unchecked(66);
    let recipient = BaseField::from_u32_unchecked(777);

    let leaf = compute_commitment_offchain(secret, nullifier, commitment_amount, token);
    let sibling = BaseField::from_u32_unchecked(222);
    let expected_root = poseidon_hash_pair(leaf, sibling);
    let refund_commitment_hash =
        compute_commitment_offchain(refund_secret, refund_nullifier, refund_amount, token);

    let witness = WithdrawMerkleWitness {
        expected_root: m31_to_qm31(expected_root),
        secret: m31_to_qm31(secret),
        nullifier: m31_to_qm31(nullifier),
        commitment_amount: m31_to_qm31(commitment_amount),
        token: m31_to_qm31(token),
        siblings: vec![m31_to_qm31(sibling)],
        index_bits_lsb: vec![QM31::from(0u32)],
        amount: m31_to_qm31(amount),
        refund_secret: m31_to_qm31(refund_secret),
        refund_nullifier: m31_to_qm31(refund_nullifier),
        refund_amount: m31_to_qm31(refund_amount),
        refund_commitment_hash: m31_to_qm31(refund_commitment_hash),
        recipient: m31_to_qm31(recipient),
    };

    let mut context = build_withdraw_merkle_context(&witness);
    context.finalize_guessed_vars();
    context.validate_circuit();
    let _proof = prove_circuit(&mut context);
}

#[test]
fn test_withdraw_merkle_circuit_with_offchain_tree() {
    let mut tree = OffchainMerkleTree::new(31);
    tree.add_leaf(BaseField::from_u32_unchecked(7));
    tree.add_leaf(BaseField::from_u32_unchecked(9));

    let secret = BaseField::from_u32_unchecked(1234);
    let nullifier = BaseField::from_u32_unchecked(333);
    let token = BaseField::from_u32_unchecked(42);
    let amount = BaseField::from_u32_unchecked(100);
    let refund_amount = BaseField::from_u32_unchecked(10);
    let commitment_amount = amount + refund_amount;
    let refund_secret = BaseField::from_u32_unchecked(555);
    let refund_nullifier = BaseField::from_u32_unchecked(777);
    let recipient = BaseField::from_u32_unchecked(999);

    let leaf = compute_commitment_offchain(secret, nullifier, commitment_amount, token);
    tree.add_leaf(leaf);

    let mut context = build_withdraw_merkle_context_from_offchain_tree(
        &tree,
        secret,
        nullifier,
        commitment_amount,
        token,
        amount,
        refund_secret,
        refund_nullifier,
        refund_amount,
        recipient,
    )
    .expect("offchain witness should build");

    context.finalize_guessed_vars();
    context.validate_circuit();
    let _proof = prove_circuit(&mut context);
}

#[test]
fn test_send_withdraw_proof_to_trusted_server() {
    use axum::body::Body;
    use base64::Engine;
    use futures::executor::block_on;
    use http_body_util::BodyExt;
    use hyper::Request;
    use secp256k1::{Message, Secp256k1, ecdsa::RecoverableSignature};
    use std::sync::Arc;
    use stwo::core::pcs::TreeVec;
    use tiny_keccak::{Hasher, Keccak};
    use tower::util::ServiceExt;
    use trusted_stwo_server::{Signer, router};
    use trusted_stwo_server::types::{VerifyAndSignRequest, VerifyAndSignResponse};

    fn qm31_to_u32s(value: QM31) -> [u32; 4] {
        let limbs = value.to_m31_array();
        [limbs[0].0, limbs[1].0, limbs[2].0, limbs[3].0]
    }

    let mut tree = OffchainMerkleTree::new(31);
    tree.add_leaf(BaseField::from_u32_unchecked(7));
    tree.add_leaf(BaseField::from_u32_unchecked(9));

    let secret = BaseField::from_u32_unchecked(1234);
    let nullifier = BaseField::from_u32_unchecked(333);
    let token = BaseField::from_u32_unchecked(42);
    let amount = BaseField::from_u32_unchecked(100);
    let refund_amount = BaseField::from_u32_unchecked(10);
    let commitment_amount = amount + refund_amount;
    let refund_secret = BaseField::from_u32_unchecked(555);
    let refund_nullifier = BaseField::from_u32_unchecked(777);
    let recipient = BaseField::from_u32_unchecked(999);

    let leaf = compute_commitment_offchain(secret, nullifier, commitment_amount, token);
    tree.add_leaf(leaf);

    let mut context = build_withdraw_merkle_context_from_offchain_tree(
        &tree,
        secret,
        nullifier,
        commitment_amount,
        token,
        amount,
        refund_secret,
        refund_nullifier,
        refund_amount,
        recipient,
    )
    .expect("offchain witness should build");

    context.finalize_guessed_vars();
    context.validate_circuit();

    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    let proof = prove_circuit_assignment(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
    );

    assert!(proof.stark_proof.is_ok(), "proof generation failed");
    let stark_proof = proof.stark_proof.expect("stark proof");
    let sizes = TreeVec::concat_cols(
        proof
            .components
            .iter()
            .map(|c| c.trace_log_degree_bounds()),
    );
    let preprocessed_column_ids = preprocessed
        .preprocessed_trace
        .ids()
        .iter()
        .map(|id| id.id.clone())
        .collect();

    let req = VerifyAndSignRequest {
        proof_id: "withdraw-proof-e2e".to_string(),
        pcs_config_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&proof.pcs_config).expect("serialize pcs config")),
        stark_proof_b64: base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&stark_proof).expect("serialize stark proof")),
        channel_salt: proof.channel_salt,
        interaction_pow_nonce: proof.interaction_pow_nonce,
        claim_log_sizes: proof.claim.log_sizes.to_vec(),
        claim_output_values: proof
            .claim
            .output_values
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        interaction_claimed_sums: proof
            .interaction_claim
            .claimed_sums
            .iter()
            .copied()
            .map(qm31_to_u32s)
            .collect(),
        stage1_trace_log_sizes: sizes[1].clone(),
        stage2_trace_log_sizes: sizes[2].clone(),
        preprocessed_trace_log_sizes: preprocessed.preprocessed_trace.log_sizes(),
        preprocessed_column_ids,
        output_addresses: preprocessed.params.output_addresses.clone(),
        n_blake_gates: preprocessed.params.n_blake_gates,
    };

    let signer = Arc::new(Signer::from_env_or_random().expect("signer"));
    let app = router(signer);

    let request = Request::builder()
        .method("POST")
        .uri("/verify-and-sign")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&req).expect("serialize request"),
        ))
        .expect("request");

    let response = block_on(app.oneshot(request)).expect("server response");
    assert_eq!(response.status(), 200, "server should accept valid proof");

    let response_bytes = block_on(response.into_body().collect())
        .expect("collect body")
        .to_bytes();
    let parsed: VerifyAndSignResponse =
        serde_json::from_slice(&response_bytes).expect("decode response");

    assert!(parsed.verified);
    assert_eq!(parsed.proof_id, "withdraw-proof-e2e");

    // Verify server signature over EVM-style message_hash that binds proof hash + claim hash.
    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut k = Keccak::v256();
        k.update(bytes);
        k.finalize(&mut out);
        out
    }

    let proof_hash = {
        let stark_proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(req.stark_proof_b64.as_bytes())
            .expect("decode stark_proof_b64");
        keccak256(&stark_proof_bytes)
    };

    let claim_hash = {
        let mut claim_bytes = Vec::new();
        claim_bytes.extend_from_slice(b"trusted-stwo-claim-v1");
        claim_bytes.extend_from_slice(&(req.claim_log_sizes.len() as u32).to_be_bytes());
        for log_size in &req.claim_log_sizes {
            claim_bytes.extend_from_slice(&log_size.to_be_bytes());
        }
        claim_bytes.extend_from_slice(&(req.claim_output_values.len() as u32).to_be_bytes());
        for limbs in &req.claim_output_values {
            for limb in limbs {
                claim_bytes.extend_from_slice(&limb.to_be_bytes());
            }
        }
        keccak256(&claim_bytes)
    };

    let expected_message_hash = {
        let mut message = Vec::new();
        message.extend_from_slice(b"trusted-stwo-message-v1");
        message.extend_from_slice(&proof_hash);
        message.extend_from_slice(&claim_hash);
        keccak256(&message)
    };

    let sig_hex = parsed.signature_hex.trim_start_matches("0x");
    let sig_bytes = hex::decode(sig_hex).expect("signature hex");
    assert_eq!(sig_bytes.len(), 65);
    let recid = secp256k1::ecdsa::RecoveryId::from_i32((parsed.signature_v - 27) as i32)
        .expect("valid v");
    let rec_sig = RecoverableSignature::from_compact(&sig_bytes[0..64], recid)
        .expect("recoverable signature");

    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(&expected_message_hash).expect("message");
    let recovered_pk = secp
        .recover_ecdsa(&msg, &rec_sig)
        .expect("recover signer public key");

    let recovered_addr = {
        let uncompressed = recovered_pk.serialize_uncompressed();
        let hash = keccak256(&uncompressed[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    };

    assert_eq!(recovered_addr, parsed.signer_address);
    assert_eq!(parsed.proof_hash_hex, hex::encode(proof_hash));
    assert_eq!(parsed.claim_hash_hex, hex::encode(claim_hash));
    assert_eq!(parsed.message_hash_hex, hex::encode(expected_message_hash));
}
