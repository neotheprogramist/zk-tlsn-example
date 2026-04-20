#[cfg(test)]
use circuit_prover::prover::prove_circuit;
use circuits::{
    context::Context,
    ops::{cond_flip, eq, guess, mul, output, sub},
};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::QM31;
use circuits::poseidon2;

use crate::offchain_merkle::{OffchainMerkleTree, poseidon_hash_pair};
use crate::paymoney_circuits::offer_circuit::compute_offer_commitment_offchain;

/// Witness for the offer-spend/cancel circuit.
///
/// Proves knowledge of all offer secret parameters (including `offer_refund_sn_hash` embedded
/// as the 7th step of the offer commitment) such that:
///   offer_commitment = H(H(H(H(H(H(H(offer_secret, offer_nullifier), amount), token),
///                             fiat_amount), currency_hash), rev_tag_hash), offer_refund_sn_hash)
/// is a leaf in the offersTree.
///
/// The output deposit is created for the seller using the same `offer_refund_sn_hash` that
/// is embedded in the offer commitment — only the seller can access it.
///
/// Public outputs (6 M31 scalars, matching `cancelOffer` contract parameter order):
///   [0] offersRoot
///   [1] offerNullifierHash = H(offer_secret, offer_nullifier)  — spend nullifier
///   [2] token
///   [3] amount
///   [4] offerCommitment
///   [5] outputCommitment = H(H(offer_refund_sn_hash, amount), token)
#[derive(Debug, Clone)]
pub struct OfferSpendCancelWitness {
    // offers tree
    pub expected_offers_root: QM31,
    pub siblings: Vec<QM31>,
    /// LSB-first bits (bit 0 = lowest tree level)
    pub index_bits_lsb: Vec<QM31>,

    // offer parameters (all secret)
    pub offer_secret: QM31,
    pub offer_nullifier: QM31,
    pub amount: QM31,
    pub token: QM31,
    pub fiat_amount: QM31,
    pub currency_hash: QM31,
    pub rev_tag_hash: QM31,
    pub offer_refund_sn_hash: QM31,

    // computed hints
    pub offer_nullifier_hash: QM31,
    pub offer_commitment_hash: QM31,
    pub output_commitment_hash: QM31,
}

fn m31_to_qm31(value: BaseField) -> QM31 {
    QM31::from(value.0)
}

fn compute_output_commitment_offchain(
    offer_refund_sn_hash: BaseField,
    amount: BaseField,
    token: BaseField,
) -> BaseField {
    let sna = poseidon_hash_pair(offer_refund_sn_hash, amount);
    poseidon_hash_pair(sna, token)
}

pub fn build_offer_spend_cancel_context(witness: &OfferSpendCancelWitness) -> Context<QM31> {
    assert_eq!(
        witness.siblings.len(),
        witness.index_bits_lsb.len(),
        "siblings and index_bits_lsb must have the same length"
    );

    let mut context = Context::<QM31>::default();
    let one = context.one();
    let zero = context.zero();

    let offers_root = guess(&mut context, witness.expected_offers_root);
    let offer_secret = guess(&mut context, witness.offer_secret);
    let offer_nullifier = guess(&mut context, witness.offer_nullifier);
    let amount = guess(&mut context, witness.amount);
    let token = guess(&mut context, witness.token);
    let fiat_amount = guess(&mut context, witness.fiat_amount);
    let currency_hash = guess(&mut context, witness.currency_hash);
    let rev_tag_hash = guess(&mut context, witness.rev_tag_hash);
    let offer_refund_sn_hash = guess(&mut context, witness.offer_refund_sn_hash);
    let offer_nullifier_hash = guess(&mut context, witness.offer_nullifier_hash);
    let offer_commitment_hash = guess(&mut context, witness.offer_commitment_hash);
    let output_commitment_hash = guess(&mut context, witness.output_commitment_hash);

    // offer_nullifier_hash == H(offer_secret, offer_nullifier)
    let computed_offer_nullifier_hash =
        poseidon2::poseidon2_hash_two(&mut context, offer_secret, offer_nullifier);
    eq(&mut context, offer_nullifier_hash, computed_offer_nullifier_hash);

    // offer_commitment == H(H(H(H(H(H(H(offer_secret, offer_nullifier), amount), token),
    //                           fiat_amount), currency_hash), rev_tag_hash), offer_refund_sn_hash)
    // reuse already-constrained offer_nullifier_hash as h0
    let h1 = poseidon2::poseidon2_hash_two(&mut context, offer_nullifier_hash, amount);
    let h2 = poseidon2::poseidon2_hash_two(&mut context, h1, token);
    let h3 = poseidon2::poseidon2_hash_two(&mut context, h2, fiat_amount);
    let h4 = poseidon2::poseidon2_hash_two(&mut context, h3, currency_hash);
    let h5 = poseidon2::poseidon2_hash_two(&mut context, h4, rev_tag_hash);
    let computed_offer_commitment =
        poseidon2::poseidon2_hash_two(&mut context, h5, offer_refund_sn_hash);
    eq(&mut context, offer_commitment_hash, computed_offer_commitment);

    // Merkle membership: offer_commitment_hash is a leaf in offersTree
    let mut current = offer_commitment_hash;
    for (&bit_value, &sibling_value) in witness.index_bits_lsb.iter().zip(witness.siblings.iter()) {
        let bit = guess(&mut context, bit_value);
        let sibling = guess(&mut context, sibling_value);

        let bit_minus_one = sub(&mut context, bit, one);
        let bit_is_binary = mul(&mut context, bit, bit_minus_one);
        eq(&mut context, bit_is_binary, zero);

        let (left, right) = cond_flip(&mut context, bit, current, sibling);
        current = poseidon2::poseidon2_hash_two(&mut context, left, right);
    }
    eq(&mut context, current, offers_root);

    // output_commitment == H(H(offer_refund_sn_hash, amount), token)
    // seller receives the full remaining amount using the key embedded in offer_commitment
    let out_sna = poseidon2::poseidon2_hash_two(&mut context, offer_refund_sn_hash, amount);
    let computed_output_commitment = poseidon2::poseidon2_hash_two(&mut context, out_sna, token);
    eq(&mut context, output_commitment_hash, computed_output_commitment);

    // Public outputs — match `cancelOffer(offersRoot, offerNullifier, token, amount,
    //                                      offerCommitment, outputCommitment)` parameter order
    output(&mut context, offers_root);
    output(&mut context, offer_nullifier_hash);
    output(&mut context, token);
    output(&mut context, amount);
    output(&mut context, offer_commitment_hash);
    output(&mut context, output_commitment_hash);

    context
}

#[allow(clippy::too_many_arguments)]
pub fn build_offer_spend_cancel_context_from_offchain_tree(
    offers_tree: &OffchainMerkleTree,
    offer_secret: BaseField,
    offer_nullifier: BaseField,
    amount: BaseField,
    token: BaseField,
    fiat_amount: BaseField,
    currency_hash: BaseField,
    rev_tag_hash: BaseField,
    offer_refund_secret: BaseField,
    offer_refund_nullifier: BaseField,
) -> Result<Context<QM31>, String> {
    let offer_refund_sn_hash = poseidon_hash_pair(offer_refund_secret, offer_refund_nullifier);

    let offer_commitment_hash = compute_offer_commitment_offchain(
        offer_secret,
        offer_nullifier,
        amount,
        token,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        offer_refund_sn_hash,
    );

    let index = offers_tree
        .find_leaf_index(offer_commitment_hash)
        .ok_or_else(|| {
            format!(
                "Offer commitment {} not found in offers tree",
                offer_commitment_hash.0
            )
        })?;
    let (siblings, is_right_bits) = offers_tree.path(index);

    let offer_nullifier_hash = poseidon_hash_pair(offer_secret, offer_nullifier);
    let output_commitment_hash =
        compute_output_commitment_offchain(offer_refund_sn_hash, amount, token);

    let witness = OfferSpendCancelWitness {
        expected_offers_root: m31_to_qm31(offers_tree.root()),
        siblings: siblings.into_iter().map(m31_to_qm31).collect(),
        index_bits_lsb: is_right_bits
            .into_iter()
            .map(|bit| QM31::from(if bit { 1u32 } else { 0u32 }))
            .collect(),
        offer_secret: m31_to_qm31(offer_secret),
        offer_nullifier: m31_to_qm31(offer_nullifier),
        amount: m31_to_qm31(amount),
        token: m31_to_qm31(token),
        fiat_amount: m31_to_qm31(fiat_amount),
        currency_hash: m31_to_qm31(currency_hash),
        rev_tag_hash: m31_to_qm31(rev_tag_hash),
        offer_refund_sn_hash: m31_to_qm31(offer_refund_sn_hash),
        offer_nullifier_hash: m31_to_qm31(offer_nullifier_hash),
        offer_commitment_hash: m31_to_qm31(offer_commitment_hash),
        output_commitment_hash: m31_to_qm31(output_commitment_hash),
    };

    Ok(build_offer_spend_cancel_context(&witness))
}

#[test]
fn test_offer_spend_cancel_circuit_unit() {
    use crate::offchain_merkle::poseidon_hash_pair as h;

    let offer_secret = BaseField::from_u32_unchecked(1001);
    let offer_nullifier = BaseField::from_u32_unchecked(1002);
    let amount = BaseField::from_u32_unchecked(70);
    let token = BaseField::from_u32_unchecked(42);
    let fiat_amount = BaseField::from_u32_unchecked(500);
    let currency_hash = BaseField::from_u32_unchecked(777);
    let rev_tag_hash = BaseField::from_u32_unchecked(888);
    let offer_refund_secret = BaseField::from_u32_unchecked(3001);
    let offer_refund_nullifier = BaseField::from_u32_unchecked(3002);

    let offer_refund_sn_hash = h(offer_refund_secret, offer_refund_nullifier);
    let offer_nullifier_hash = h(offer_secret, offer_nullifier);
    let offer_commitment_hash = compute_offer_commitment_offchain(
        offer_secret,
        offer_nullifier,
        amount,
        token,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        offer_refund_sn_hash,
    );
    let output_commitment_hash =
        compute_output_commitment_offchain(offer_refund_sn_hash, amount, token);

    let sibling = BaseField::from_u32_unchecked(333);
    let expected_offers_root = h(offer_commitment_hash, sibling);

    let witness = OfferSpendCancelWitness {
        expected_offers_root: m31_to_qm31(expected_offers_root),
        siblings: vec![m31_to_qm31(sibling)],
        index_bits_lsb: vec![QM31::from(0u32)],
        offer_secret: m31_to_qm31(offer_secret),
        offer_nullifier: m31_to_qm31(offer_nullifier),
        amount: m31_to_qm31(amount),
        token: m31_to_qm31(token),
        fiat_amount: m31_to_qm31(fiat_amount),
        currency_hash: m31_to_qm31(currency_hash),
        rev_tag_hash: m31_to_qm31(rev_tag_hash),
        offer_refund_sn_hash: m31_to_qm31(offer_refund_sn_hash),
        offer_nullifier_hash: m31_to_qm31(offer_nullifier_hash),
        offer_commitment_hash: m31_to_qm31(offer_commitment_hash),
        output_commitment_hash: m31_to_qm31(output_commitment_hash),
    };

    let mut context = build_offer_spend_cancel_context(&witness);
    context.finalize_guessed_vars();
    context.validate_circuit();
    let _proof = prove_circuit(&mut context);
}

#[test]
fn test_offer_spend_cancel_circuit_with_offchain_tree() {
    let offer_secret = BaseField::from_u32_unchecked(1234);
    let offer_nullifier = BaseField::from_u32_unchecked(5678);
    let amount = BaseField::from_u32_unchecked(70);
    let token = BaseField::from_u32_unchecked(42);
    let fiat_amount = BaseField::from_u32_unchecked(500);
    let currency_hash = BaseField::from_u32_unchecked(777);
    let rev_tag_hash = BaseField::from_u32_unchecked(888);
    let offer_refund_secret = BaseField::from_u32_unchecked(3001);
    let offer_refund_nullifier = BaseField::from_u32_unchecked(3002);

    let offer_refund_sn_hash =
        poseidon_hash_pair(offer_refund_secret, offer_refund_nullifier);

    let offer_commitment = compute_offer_commitment_offchain(
        offer_secret,
        offer_nullifier,
        amount,
        token,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        offer_refund_sn_hash,
    );

    let mut offers_tree = OffchainMerkleTree::new(31);
    offers_tree.add_leaf(BaseField::from_u32_unchecked(11));
    offers_tree.add_leaf(BaseField::from_u32_unchecked(22));
    offers_tree.add_leaf(offer_commitment);

    let mut context = build_offer_spend_cancel_context_from_offchain_tree(
        &offers_tree,
        offer_secret,
        offer_nullifier,
        amount,
        token,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        offer_refund_secret,
        offer_refund_nullifier,
    )
    .expect("offchain witness should build");

    context.finalize_guessed_vars();
    context.validate_circuit();
    let _proof = prove_circuit(&mut context);
}
