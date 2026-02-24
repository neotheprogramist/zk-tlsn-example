use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX,
};

use crate::poseidon_hash::{
    apply_external_round_matrix, apply_internal_round_matrix, EXTERNAL_ROUND_CONSTS,
    INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
};

use super::trace::N_CHAIN_ROWS;
use crate::relations::LeafRelation;

#[derive(Clone)]
pub struct PoseidonChainEval {
    pub log_n_rows: u32,
    pub is_active_id: PreProcessedColumnId,
    pub is_step_id: PreProcessedColumnId,
    pub is_last_id: PreProcessedColumnId,
    pub leaf_relation: LeafRelation,
    pub leaf_multiplicity: u32,
    pub claimed_sum: stwo::core::fields::qm31::SecureField,
}

impl FrameworkEval for PoseidonChainEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 3 // LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_active_val = eval.get_preprocessed_column(self.is_active_id.clone());
        let is_step_val = eval.get_preprocessed_column(self.is_step_id.clone());
        let is_last_val = eval.get_preprocessed_column(self.is_last_id.clone());

        // Read initial state (16 elements)
        let [initial_state_first_curr, initial_state_first_next] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);

        // Read the rest of initial_state (cols 1-15) normally with offset [0]
        let initial_state_curr: [E::F; N_STATE] = std::array::from_fn(|i| {
            if i == 0 {
                initial_state_first_curr.clone()
            } else {
                eval.next_trace_mask()
            }
        });

        // Constraint: state[2..16] must be zero (capacity)
        for i in 2..N_STATE {
            eval.add_constraint(is_active_val.clone() * initial_state_curr[i].clone());
        }

        // Poseidon2 permutation constraints 
        let mut state = initial_state_curr.clone();

        // Apply initial external round matrix 
        apply_external_round_matrix(&mut state);

        // First 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            // Add round constants
            for i in 0..N_STATE {
                state[i] = state[i].clone() + E::F::from(EXTERNAL_ROUND_CONSTS[round][i]);
            }
            let initial_state = state.clone();

            // Step 1: Square the state (x^2)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }

            // Step 2: Square again (x^4)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }

            // Step 3: Multiply by initial state (x^5) and apply external matrix
            state = std::array::from_fn(|i| state[i].clone() * initial_state[i].clone());
            apply_external_round_matrix(&mut state);
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            // Add round constant (only to first element)
            state[0] = state[0].clone() + E::F::from(INTERNAL_ROUND_CONSTS[round]);
            let initial_state_0 = state[0].clone();

            // Step 1: Square the first element (x^2)
            state[0] = state[0].clone() * state[0].clone();
            let mask = eval.next_trace_mask();
            eval.add_constraint(is_active_val.clone() * (state[0].clone() - mask.clone()));
            state[0] = mask; 

            // Step 2: Square again (x^4)
            state[0] = state[0].clone() * state[0].clone();
            let mask = eval.next_trace_mask();
            eval.add_constraint(is_active_val.clone() * (state[0].clone() - mask.clone()));
            state[0] = mask; 

            // Step 3: Multiply by initial state[0] (x^5)
            state[0] = state[0].clone() * initial_state_0;
            let mask = eval.next_trace_mask();
            eval.add_constraint(is_active_val.clone() * (state[0].clone() - mask.clone()));
            state[0] = mask; 

            // Step 4: Apply internal round matrix and VERIFY all 16 elements
            apply_internal_round_matrix(&mut state);
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }
        }

        // Last 4 full rounds 
        for round in 0..N_HALF_FULL_ROUNDS {
            // Add round constants
            for i in 0..N_STATE {
                state[i] = state[i].clone()
                    + E::F::from(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
            }
            let initial_state = state.clone();

            // Step 1: Square the state (x^2)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }

            // Step 2: Square again (x^4)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }

            // Step 3: Multiply by initial state (x^5) and apply external matrix
            state = std::array::from_fn(|i| state[i].clone() * initial_state[i].clone());
            apply_external_round_matrix(&mut state);
            for i in 0..N_STATE {
                let mask = eval.next_trace_mask();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask; 
            }
        }

        // Final state is already in `state` after last round
        // Chain constraint: final_state[0] at current row = initial_state[0] at next row
        eval.add_constraint(is_step_val * (state[0].clone() - initial_state_first_next));

        let leaf_value = state[0].clone();

        // LogUp: yield leaf with configurable multiplicity
        // For deposit chain: multiplicity=2 (consumed by Merkle + Scheduler)
        // For refund chain: multiplicity=1 (consumed by Scheduler only)
        let multiplicity =
            is_last_val * E::F::from(BaseField::from_u32_unchecked(self.leaf_multiplicity));
        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            multiplicity.into(),
            &[leaf_value],
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type PoseidonChainComponent = FrameworkComponent<PoseidonChainEval>;

pub fn gen_is_active_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..N_CHAIN_ROWS.min(n_rows) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_active_column_id(log_size: u32, component_name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_active_{}_{}", component_name, log_size),
    }
}

pub fn gen_is_step_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..(N_CHAIN_ROWS.saturating_sub(1)).min(n_rows) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_step_column_id(log_size: u32, component_name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_step_{}_{}", component_name, log_size),
    }
}

pub fn is_first_column_id(log_size: u32) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_first_{}", log_size),
    }
}

pub fn gen_is_last_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    if N_CHAIN_ROWS > 0 && N_CHAIN_ROWS - 1 < n_rows {
        col.set(N_CHAIN_ROWS - 1, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_last_column_id(log_size: u32, component_name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_last_{}_{}", component_name, log_size),
    }
}
