mod constraints;
mod generate;

use constraints::eval_blake_scheduler_constraints;
pub use generate::{compute_commitment_hash, gen_interaction_trace, gen_trace};
use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval,
    relation,
};

use super::N_ROUND_INPUT_FELTS;
use super::round::RoundElements;
use crate::blake3::BlakeXorElements;

pub type BlakeSchedulerComponent = FrameworkComponent<BlakeSchedulerEval>;

relation!(BlakeElements, N_ROUND_INPUT_FELTS);

pub struct BlakeSchedulerEval {
    pub log_size: u32,
    pub blake_lookup_elements: BlakeElements,
    pub round_lookup_elements: RoundElements,
    pub xor_lookup_elements: BlakeXorElements,
    pub committed_hash_words: [u32; 8],
    pub claimed_sum: SecureField,
}
impl FrameworkEval for BlakeSchedulerEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        eval_blake_scheduler_constraints(
            &mut eval,
            &self.blake_lookup_elements,
            &self.round_lookup_elements,
            &self.xor_lookup_elements,
            self.committed_hash_words,
        );

        eval
    }
}

pub fn blake_scheduler_info() -> stwo_constraint_framework::InfoEvaluator {
    use stwo_constraint_framework::InfoEvaluator;

    let component = BlakeSchedulerEval {
        log_size: 1,
        blake_lookup_elements: BlakeElements::dummy(),
        round_lookup_elements: RoundElements::dummy(),
        xor_lookup_elements: BlakeXorElements::dummy(),
        committed_hash_words: [0u32; 8],
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}
