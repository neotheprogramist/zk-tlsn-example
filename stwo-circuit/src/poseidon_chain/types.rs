use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;

use super::trace::N_COLUMNS;

#[derive(Clone, Debug)]
pub struct ChainInputs {
    pub input1_a: BaseField,
    pub input1_b: BaseField,
    pub input2: BaseField,
    pub input3: BaseField,
}

impl ChainInputs {
    pub fn for_deposit(
        secret: BaseField,
        nullifier: BaseField,
        commitment_amount: BaseField,
        token_address: BaseField,
    ) -> Self {
        Self {
            input1_a: secret,
            input1_b: nullifier,
            input2: commitment_amount,
            input3: token_address,
        }
    }

    pub fn for_refund(
        secret: BaseField,
        nullifier: BaseField,
        amount: BaseField,
        token_address: BaseField,
    ) -> Self {
        Self {
            input1_a: secret,
            input1_b: nullifier,
            input2: amount,
            input3: token_address,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChainOutputs {
    pub leaf: BaseField,
}

#[derive(Clone, Debug)]
pub struct ChainStatement0 {
    pub log_size: u32,
}

impl ChainStatement0 {
    pub fn mix_into(&self, channel: &mut impl stwo::core::channel::Channel) {
        channel.mix_u64(self.log_size as u64);
    }

    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec(vec![
            vec![self.log_size; 3],
            vec![self.log_size; N_COLUMNS],
            vec![self.log_size; 4],
        ])
    }
}

#[derive(Clone, Debug)]
pub struct ChainStatement1 {
    pub claimed_sum: SecureField,
}

impl ChainStatement1 {
    pub fn mix_into(&self, channel: &mut impl stwo::core::channel::Channel) {
        channel.mix_felts(&[self.claimed_sum]);
    }
}
