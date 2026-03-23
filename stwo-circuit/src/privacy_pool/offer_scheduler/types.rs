use stwo::core::pcs::TreeVec;

pub const N_COLUMNS: usize = 8;

#[derive(Clone, Debug)]
pub struct OfferSchedulerStatement0 {
    pub log_size: u32,
}

impl OfferSchedulerStatement0 {
    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec(vec![
            vec![self.log_size; 1],         // Tree 0: 1 preprocessed column (is_first)
            vec![self.log_size; N_COLUMNS], // Tree 1: 8 base trace columns
            vec![self.log_size; 12], // Tree 2: 12 interaction trace columns (3 logup cols × 4)
        ])
    }
}
