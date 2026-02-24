use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;

use super::trace::N_COLUMNS;

#[derive(Debug, Clone)]
pub struct MerkleInputs {
    pub leaf: BaseField,
    pub siblings: Vec<BaseField>,
    pub index: u32,
    pub expected_root: BaseField,
}

impl MerkleInputs {
    pub fn new(
        leaf: BaseField,
        siblings: Vec<BaseField>,
        index: u32,
        expected_root: BaseField,
    ) -> Self {
        Self {
            leaf,
            siblings,
            index,
            expected_root,
        }
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleOutputs {
    pub computed_root: BaseField,
    pub is_valid: bool,
}

impl MerkleOutputs {
    pub fn new(computed_root: BaseField, expected_root: BaseField) -> Self {
        Self {
            computed_root,
            is_valid: computed_root == expected_root,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MerkleStatement0 {
    pub log_size: u32,
}

impl MerkleStatement0 {
    pub fn mix_into(&self, channel: &mut impl stwo::core::channel::Channel) {
        channel.mix_u64(self.log_size as u64);
    }

    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec(vec![
            vec![self.log_size; 4],         // Tree 0: 4 preprocessed columns (is_active, is_step, is_first, is_last)
            vec![self.log_size; N_COLUMNS], // Tree 1: 667 base trace columns (1 index_bit + 666 Poseidon)
            vec![self.log_size; 4],         // Tree 2: 4 interaction trace columns (finalize_last)
        ])
    }
}

#[derive(Clone, Debug)]
pub struct MerkleStatement1 {
    pub claimed_sum: SecureField,
}

impl MerkleStatement1 {
    pub fn mix_into(&self, channel: &mut impl stwo::core::channel::Channel) {
        channel.mix_felts(&[self.claimed_sum]);
    }
}
