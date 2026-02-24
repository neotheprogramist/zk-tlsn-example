use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;

pub const N_COLUMNS: usize = 6;

#[derive(Clone, Debug)]
pub struct SchedulerStatement {
    pub expected_root: BaseField,
    pub depth: u32,
    pub nullifier: BaseField,
    pub token_address: BaseField,
    pub amount: BaseField,
    pub refund_commitment_hash: BaseField,
    pub recipient: BaseField,
}

impl SchedulerStatement {
    pub fn new(
        expected_root: BaseField,
        depth: u32,
        nullifier: BaseField,
        token_address: BaseField,
        amount: BaseField,
        refund_commitment_hash: BaseField,
        recipient: BaseField,
    ) -> Self {
        Self {
            expected_root,
            depth,
            nullifier,
            token_address,
            amount,
            refund_commitment_hash,
            recipient,
        }
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[
            self.expected_root.into(),
            self.nullifier.into(),
            self.token_address.into(),
            self.amount.into(),
            self.refund_commitment_hash.into(),
            self.recipient.into(),
        ]);
        channel.mix_u64(self.depth as u64);
    }
}

#[derive(Clone, Debug)]
pub struct SchedulerStatement0 {
    pub log_size: u32,
}

impl SchedulerStatement0 {
    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
    }

    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec(vec![
            vec![self.log_size; 1],  // Tree 0: 1 preprocessed column (is_first)
            vec![self.log_size; N_COLUMNS], // Tree 1: 6 base trace columns
            vec![self.log_size; 12], // Tree 2: 12 interaction trace columns (3 logup cols × 4)
        ])
    }
}

#[derive(Clone, Debug)]
pub struct SchedulerStatement1 {
    pub claimed_sum: SecureField,
}
