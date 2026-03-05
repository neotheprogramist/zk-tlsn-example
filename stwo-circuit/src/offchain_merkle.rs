use stwo::core::fields::m31::BaseField;

use crate::poseidon_hash::{
    EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
    apply_external_round_matrix, apply_internal_round_matrix, pow5,
};

#[derive(Debug, Clone)]
pub struct OffchainMerkleTree {
    sibling_depth: usize,
    precomputed: Vec<BaseField>,
    left_path: Vec<BaseField>,
    layers: Vec<Vec<BaseField>>,
    leaves: Vec<BaseField>,
    free_index: u64,
}

impl OffchainMerkleTree {
    pub fn new(sibling_depth: usize) -> Self {
        assert!(sibling_depth > 0, "sibling_depth must be > 0");

        let precomputed = precomputed_hashes(sibling_depth);
        let left_path = precomputed.clone();
        let layers = vec![Vec::new(); sibling_depth + 1];

        Self {
            sibling_depth,
            precomputed,
            left_path,
            layers,
            leaves: Vec::new(),
            free_index: 0,
        }
    }

    pub fn with_leaves(sibling_depth: usize, leaves: impl IntoIterator<Item = BaseField>) -> Self {
        let mut tree = Self::new(sibling_depth);
        for leaf in leaves {
            tree.add_leaf(leaf);
        }
        tree
    }

    pub fn sibling_depth(&self) -> usize {
        self.sibling_depth
    }

    pub fn leaf_count(&self) -> u64 {
        self.free_index
    }

    pub fn leaves(&self) -> &[BaseField] {
        &self.leaves
    }

    pub fn root(&self) -> BaseField {
        self.left_path[self.sibling_depth]
    }

    pub fn add_leaf(&mut self, leaf: BaseField) -> u64 {
        if let Some(index) = self.find_leaf_index(leaf) {
            return index as u64;
        }

        let inserted_index = self.free_index;
        self.free_index += 1;

        let mut hash_val = leaf;
        let mut index = inserted_index as usize;
        self.layers[0].push(leaf);

        for level in 1..=self.sibling_depth {
            if index % 2 == 0 {
                self.left_path[level - 1] = hash_val;
                hash_val = poseidon_hash_pair(hash_val, self.precomputed[level - 1]);
            } else {
                hash_val = poseidon_hash_pair(self.left_path[level - 1], hash_val);
            }

            index /= 2;
            if self.layers[level].len() > index {
                self.layers[level][index] = hash_val;
            } else {
                self.layers[level].push(hash_val);
            }
        }

        self.left_path[self.sibling_depth] = hash_val;
        self.leaves.push(leaf);
        inserted_index
    }

    pub fn find_leaf_index(&self, leaf: BaseField) -> Option<usize> {
        self.layers[0].iter().position(|&x| x == leaf)
    }

    pub fn path(&self, mut index: usize) -> (Vec<BaseField>, Vec<bool>) {
        assert!(index < self.layers[0].len(), "leaf index out of bounds");

        let mut siblings = Vec::with_capacity(self.sibling_depth);
        let mut is_right = Vec::with_capacity(self.sibling_depth);

        for level in 0..self.sibling_depth {
            let right = index % 2 == 1;
            let sibling = if right {
                self.layers[level][index - 1]
            } else {
                self.layers[level]
                    .get(index + 1)
                    .copied()
                    .unwrap_or(self.precomputed[level])
            };

            siblings.push(sibling);
            is_right.push(right);
            index /= 2;
        }

        (siblings, is_right)
    }
}

pub fn precomputed_hashes(sibling_depth: usize) -> Vec<BaseField> {
    let mut values = Vec::with_capacity(sibling_depth + 1);
    let mut current = poseidon_hash_pair(
        BaseField::from_u32_unchecked(0),
        BaseField::from_u32_unchecked(0),
    );
    values.push(current);

    for _ in 1..=sibling_depth {
        current = poseidon_hash_pair(current, current);
        values.push(current);
    }

    values
}

pub fn poseidon_hash_pair(left: BaseField, right: BaseField) -> BaseField {
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = left;
    state[1] = right;

    apply_external_round_matrix(&mut state);

    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] += EXTERNAL_ROUND_CONSTS[round][i];
            state[i] = pow5(state[i]);
        }
        apply_external_round_matrix(&mut state);
    }

    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += INTERNAL_ROUND_CONSTS[round];
        state[0] = pow5(state[0]);
        apply_internal_round_matrix(&mut state);
    }

    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] += EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
            state[i] = pow5(state[i]);
        }
        apply_external_round_matrix(&mut state);
    }

    state[0]
}

#[cfg(test)]
mod tests {
    use stwo::core::fields::m31::BaseField;

    use super::{OffchainMerkleTree, poseidon_hash_pair};
    use crate::merkle_membership::{MerkleInputs, gen_merkle_trace};

    #[test]
    fn precomputed_root_matches_empty_tree() {
        let tree = OffchainMerkleTree::new(31);
        let expected = (0..31).fold(
            poseidon_hash_pair(
                BaseField::from_u32_unchecked(0),
                BaseField::from_u32_unchecked(0),
            ),
            |acc, _| poseidon_hash_pair(acc, acc),
        );
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn path_and_root_match_merkle_trace_for_multiple_leaves() {
        let mut tree = OffchainMerkleTree::new(31);

        let leaves = [
            BaseField::from_u32_unchecked(123),
            BaseField::from_u32_unchecked(456),
            BaseField::from_u32_unchecked(789),
        ];
        for leaf in leaves {
            tree.add_leaf(leaf);
        }

        for leaf in leaves {
            let index = tree.find_leaf_index(leaf).expect("leaf index");
            let (siblings, _) = tree.path(index);
            let inputs = MerkleInputs::new(leaf, siblings, index as u32, tree.root());
            let (_, computed_root) = gen_merkle_trace(8, &inputs);
            assert_eq!(computed_root, tree.root());
        }
    }
}
