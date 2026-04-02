#[cfg(test)]
use circuit_prover::prover::prove_circuit;
use circuits::{
    context::Context,
    ops::{cond_flip, eq, guess, mul, output, sub},
};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::QM31;
use circuits::poseidon2;

use crate::offchain_merkle::OffchainMerkleTree;

#[derive(Debug, Clone)]
pub struct WithdrawMerkleWitness {
    pub leaf: QM31,
    pub siblings: Vec<QM31>,
    /// LSB-first bits (bit 0 = lowest tree level)
    pub index_bits_lsb: Vec<QM31>,
    pub expected_root: QM31,
    pub nullifier: QM31,
    pub amount: QM31,
    pub token: QM31,
}

fn m31_to_qm31(value: BaseField) -> QM31 {
    QM31::from(value.0)
}

/// Builds a withdraw circuit aligned with:
/// - raw STWO Merkle trace (`index_bit` decides `(left, right)` each level),
/// - Solidity `MerkleTreeLib::addLeaf` direction logic (left when bit=0, right when bit=1).
///
/// Public outputs order: `[root, nullifier, amount, token]`.
pub fn build_withdraw_merkle_context(witness: &WithdrawMerkleWitness) -> Context<QM31> {
    assert_eq!(
        witness.siblings.len(),
        witness.index_bits_lsb.len(),
        "siblings and index_bits_lsb must have the same length"
    );

    let mut context = Context::<QM31>::default();
    let one = context.one();
    let zero = context.zero();

    let mut current = guess(&mut context, witness.leaf);

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

    let expected_root = guess(&mut context, witness.expected_root);
    eq(&mut context, current, expected_root);

    let nullifier = guess(&mut context, witness.nullifier);
    let amount = guess(&mut context, witness.amount);
    let token = guess(&mut context, witness.token);

    output(&mut context, expected_root);
    output(&mut context, nullifier);
    output(&mut context, amount);
    output(&mut context, token);

    context
}

/// Builds withdraw context directly from local offchain Merkle tree data.
///
/// Full compatibility guarantees:
/// - siblings and direction bits come from `OffchainMerkleTree::path`,
/// - bit ordering is LSB-first,
/// - root equals `tree.root()`,
/// - bit semantics match Solidity/raw STWO (`is_right=true => bit=1`).
pub fn build_withdraw_merkle_context_from_offchain_tree(
    tree: &OffchainMerkleTree,
    leaf: BaseField,
    nullifier: BaseField,
    amount: BaseField,
    token: BaseField,
) -> Result<Context<QM31>, String> {
    let index = tree
        .find_leaf_index(leaf)
        .ok_or_else(|| format!("Leaf {} not found in offchain tree", leaf.0))?;

    let (siblings, is_right_bits) = tree.path(index);

    let witness = WithdrawMerkleWitness {
        leaf: m31_to_qm31(leaf),
        siblings: siblings.into_iter().map(m31_to_qm31).collect(),
        index_bits_lsb: is_right_bits
            .into_iter()
            .map(|bit| QM31::from(if bit { 1u32 } else { 0u32 }))
            .collect(),
        expected_root: m31_to_qm31(tree.root()),
        nullifier: m31_to_qm31(nullifier),
        amount: m31_to_qm31(amount),
        token: m31_to_qm31(token),
    };

    Ok(build_withdraw_merkle_context(&witness))
}

#[test]
fn test_withdraw_merkle_circuit() {
    // Build a 1-level path and compute a consistent expected root with the same Poseidon gate.
    let leaf = QM31::from(111u32);
    let sibling = QM31::from(222u32);
    let bit = QM31::from(0u32);

    let expected_root = {
        let mut tmp = Context::<QM31>::default();
        let l = guess(&mut tmp, leaf);
        let s = guess(&mut tmp, sibling);
        let b = guess(&mut tmp, bit);
        let (left, right) = cond_flip(&mut tmp, b, l, s);
        let root_var = poseidon2::poseidon2_hash_two(&mut tmp, left, right);
        tmp.get(root_var)
    };

    let witness = WithdrawMerkleWitness {
        leaf,
        siblings: vec![sibling],
        index_bits_lsb: vec![bit],
        expected_root,
        nullifier: QM31::from(333u32),
        amount: QM31::from(100u32),
        token: QM31::from(42u32),
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

    let leaf = BaseField::from_u32_unchecked(123456);
    tree.add_leaf(leaf);

    let mut context = build_withdraw_merkle_context_from_offchain_tree(
        &tree,
        leaf,
        BaseField::from_u32_unchecked(333),
        BaseField::from_u32_unchecked(100),
        BaseField::from_u32_unchecked(42),
    )
    .expect("offchain witness should build");

    context.finalize_guessed_vars();
    context.validate_circuit();
    let _proof = prove_circuit(&mut context);
}
