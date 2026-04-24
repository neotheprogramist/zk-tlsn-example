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


#[derive(Debug, Clone)]
pub struct OfferMerkleWitness {
    // deposit data
    pub expected_root: QM31,
    pub secret: QM31,
    pub nullifier: QM31,
    pub commitment_amount: QM31,
    pub token: QM31,
    pub siblings: Vec<QM31>,
    /// LSB-first bits (bit 0 = lowest tree level)
    pub index_bits_lsb: Vec<QM31>,

    // offer amount
    pub amount: QM31,

    // offer commitment data
    pub offer_secret: QM31,
    pub offer_nullifier: QM31,
    pub fiat_amount: QM31,
    pub currency_hash: QM31,
    pub rev_tag_hash: QM31,
    pub offer_commitment_hash: QM31,

    // post-use seller refund key: H(refund_secret, refund_nullifier)
    // embedded as 7th step in offer_commitment so only the seller can claim the refund
    pub offer_refund_sn_hash: QM31,

    // initial change from deposit split (deposit_amount - offer_amount)
    pub refund_secret: QM31,
    pub refund_nullifier: QM31,
    pub refund_amount: QM31,
    pub refund_commitment_hash: QM31,

    // optional binding to external metadata
    pub secret_hash: QM31,
}

fn m31_to_qm31(value: BaseField) -> QM31 {
    QM31::from(value.0)
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

pub fn compute_offer_commitment_offchain(
    offer_secret: BaseField,
    offer_nullifier: BaseField,
    amount: BaseField,
    token: BaseField,
    fiat_amount: BaseField,
    currency_hash: BaseField,
    rev_tag_hash: BaseField,
    offer_refund_sn_hash: BaseField,
) -> BaseField {
    let h0 = poseidon_hash_pair(offer_secret, offer_nullifier);
    let h1 = poseidon_hash_pair(h0, amount);
    let h2 = poseidon_hash_pair(h1, token);
    let h3 = poseidon_hash_pair(h2, fiat_amount);
    let h4 = poseidon_hash_pair(h3, currency_hash);
    let h5 = poseidon_hash_pair(h4, rev_tag_hash);
    poseidon_hash_pair(h5, offer_refund_sn_hash)
}

pub fn build_offer_merkle_context(witness: &OfferMerkleWitness) -> Context<QM31> {
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

    let offer_secret = guess(&mut context, witness.offer_secret);
    let offer_nullifier = guess(&mut context, witness.offer_nullifier);
    let fiat_amount = guess(&mut context, witness.fiat_amount);
    let currency_hash = guess(&mut context, witness.currency_hash);
    let rev_tag_hash = guess(&mut context, witness.rev_tag_hash);
    let offer_commitment_hash = guess(&mut context, witness.offer_commitment_hash);
    let offer_refund_sn_hash = guess(&mut context, witness.offer_refund_sn_hash);

    let refund_secret = guess(&mut context, witness.refund_secret);
    let refund_nullifier = guess(&mut context, witness.refund_nullifier);
    let refund_amount = guess(&mut context, witness.refund_amount);
    let refund_commitment_hash = guess(&mut context, witness.refund_commitment_hash);

    let secret_hash = guess(&mut context, witness.secret_hash);

    // commitment_amount == amount + refund_amount
    let neg_refund_amount = sub(&mut context, zero, refund_amount);
    let amount_plus_refund = sub(&mut context, amount, neg_refund_amount);
    eq(&mut context, commitment_amount, amount_plus_refund);

    // membership leaf = H(H(H(secret, nullifier), commitment_amount), token)
    let secret_nullifier_hash = poseidon2::poseidon2_hash_two(&mut context, secret, nullifier);
    let secret_nullifier_amount_hash =
        poseidon2::poseidon2_hash_two(&mut context, secret_nullifier_hash, commitment_amount);
    let leaf = poseidon2::poseidon2_hash_two(&mut context, secret_nullifier_amount_hash, token);

    let mut current = leaf;
    for (&bit_value, &sibling_value) in witness
        .index_bits_lsb
        .iter()
        .zip(witness.siblings.iter())
    {
        let bit = guess(&mut context, bit_value);
        let sibling = guess(&mut context, sibling_value);

        let bit_minus_one = sub(&mut context, bit, one);
        let bit_is_binary = mul(&mut context, bit, bit_minus_one);
        eq(&mut context, bit_is_binary, zero);

        let (left, right) = cond_flip(&mut context, bit, current, sibling);
        current = poseidon2::poseidon2_hash_two(&mut context, left, right);
    }
    eq(&mut context, current, root);

    // refund commitment hash
    let refund_sn_hash = poseidon2::poseidon2_hash_two(&mut context, refund_secret, refund_nullifier);
    let refund_sna_hash = poseidon2::poseidon2_hash_two(&mut context, refund_sn_hash, refund_amount);
    let refund_computed = poseidon2::poseidon2_hash_two(&mut context, refund_sna_hash, token);
    eq(&mut context, refund_commitment_hash, refund_computed);

    // offer commitment hash (7-step chain ending with offer_refund_sn_hash)
    let offer_h0 = poseidon2::poseidon2_hash_two(&mut context, offer_secret, offer_nullifier);
    let offer_h1 = poseidon2::poseidon2_hash_two(&mut context, offer_h0, amount);
    let offer_h2 = poseidon2::poseidon2_hash_two(&mut context, offer_h1, token);
    let offer_h3 = poseidon2::poseidon2_hash_two(&mut context, offer_h2, fiat_amount);
    let offer_h4 = poseidon2::poseidon2_hash_two(&mut context, offer_h3, currency_hash);
    let offer_h5 = poseidon2::poseidon2_hash_two(&mut context, offer_h4, rev_tag_hash);
    let offer_computed = poseidon2::poseidon2_hash_two(&mut context, offer_h5, offer_refund_sn_hash);
    eq(&mut context, offer_commitment_hash, offer_computed);

    // optional binding: secret_hash == H(secret, secret)
    let computed_secret_hash = poseidon2::poseidon2_hash_two(&mut context, secret, secret);
    eq(&mut context, secret_hash, computed_secret_hash);

    // Public outputs expected by contract/server:
    //   [0] root, [1] nullifier, [2] token, [3] amount,
    //   [4] offerCommitment, [5] initialRefundCommitment, [6] offerRefundSnHash,
    //   [7] fiatAmount, [8] currencyHash, [9] revTagHash
    output(&mut context, root);
    output(&mut context, nullifier);
    output(&mut context, token);
    output(&mut context, amount);
    output(&mut context, offer_commitment_hash);
    output(&mut context, refund_commitment_hash);
    output(&mut context, offer_refund_sn_hash);
    output(&mut context, fiat_amount);
    output(&mut context, currency_hash);
    output(&mut context, rev_tag_hash);


    context
}

#[allow(clippy::too_many_arguments)]
pub fn build_offer_merkle_context_from_offchain_tree(
    tree: &OffchainMerkleTree,
    secret: BaseField,
    nullifier: BaseField,
    commitment_amount: BaseField,
    token: BaseField,
    amount: BaseField,
    offer_secret: BaseField,
    offer_nullifier: BaseField,
    fiat_amount: BaseField,
    currency_hash: BaseField,
    rev_tag_hash: BaseField,
    // post-use seller refund: only H(secret, nullifier) is embedded in the offer commitment
    offer_refund_secret: BaseField,
    offer_refund_nullifier: BaseField,
    // initial change commitment (deposit_amount - offer_amount)
    refund_secret: BaseField,
    refund_nullifier: BaseField,
    refund_amount: BaseField,
) -> Result<Context<QM31>, String> {
    let leaf = compute_commitment_offchain(secret, nullifier, commitment_amount, token);
    let index = tree
        .find_leaf_index(leaf)
        .ok_or_else(|| format!("Leaf {} not found in offchain tree", leaf.0))?;
    let (siblings, is_right_bits) = tree.path(index);

    let offer_refund_sn_hash = poseidon_hash_pair(offer_refund_secret, offer_refund_nullifier);
    let refund_commitment_hash =
        compute_commitment_offchain(refund_secret, refund_nullifier, refund_amount, token);
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

    let secret_hash = poseidon_hash_pair(secret, secret);

    let witness = OfferMerkleWitness {
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
        offer_secret: m31_to_qm31(offer_secret),
        offer_nullifier: m31_to_qm31(offer_nullifier),
        fiat_amount: m31_to_qm31(fiat_amount),
        currency_hash: m31_to_qm31(currency_hash),
        rev_tag_hash: m31_to_qm31(rev_tag_hash),
        offer_commitment_hash: m31_to_qm31(offer_commitment_hash),
        offer_refund_sn_hash: m31_to_qm31(offer_refund_sn_hash),
        refund_secret: m31_to_qm31(refund_secret),
        refund_nullifier: m31_to_qm31(refund_nullifier),
        refund_amount: m31_to_qm31(refund_amount),
        refund_commitment_hash: m31_to_qm31(refund_commitment_hash),
        secret_hash: m31_to_qm31(secret_hash),
    };

    Ok(build_offer_merkle_context(&witness))
}

#[test]
fn test_offer_merkle_circuit_with_offchain_tree() {
    let mut tree = OffchainMerkleTree::new(31);
    tree.add_leaf(BaseField::from_u32_unchecked(7));
    tree.add_leaf(BaseField::from_u32_unchecked(9));

    let secret = BaseField::from_u32_unchecked(1234);
    let nullifier = BaseField::from_u32_unchecked(333);
    let token = BaseField::from_u32_unchecked(42);
    let amount = BaseField::from_u32_unchecked(70);
    let refund_amount = BaseField::from_u32_unchecked(30);
    let commitment_amount = amount + refund_amount;

    let offer_secret = BaseField::from_u32_unchecked(111);
    let offer_nullifier = BaseField::from_u32_unchecked(222);
    let fiat_amount = BaseField::from_u32_unchecked(1000);
    let currency_hash = BaseField::from_u32_unchecked(777);
    let rev_tag_hash = BaseField::from_u32_unchecked(888);
    let offer_refund_secret = BaseField::from_u32_unchecked(991);
    let offer_refund_nullifier = BaseField::from_u32_unchecked(992);

    let refund_secret = BaseField::from_u32_unchecked(555);
    let refund_nullifier = BaseField::from_u32_unchecked(666);

    let leaf = compute_commitment_offchain(secret, nullifier, commitment_amount, token);
    tree.add_leaf(leaf);

    let mut context = build_offer_merkle_context_from_offchain_tree(
        &tree,
        secret,
        nullifier,
        commitment_amount,
        token,
        amount,
        offer_secret,
        offer_nullifier,
        fiat_amount,
        currency_hash,
        rev_tag_hash,
        offer_refund_secret,
        offer_refund_nullifier,
        refund_secret,
        refund_nullifier,
        refund_amount,
    )
    .expect("offchain witness should build");

    context.finalize_guessed_vars();
    context.validate_circuit();
    let _proof = prove_circuit(&mut context);
}