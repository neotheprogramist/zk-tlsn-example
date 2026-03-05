use num_traits::One;
use stwo::{
    core::{
        fields::m31::BaseField, poly::circle::CanonicCoset,
        utils::bit_reverse_coset_to_circle_domain_order,
    },
    prover::{
        backend::{Col, Column, simd::SimdBackend},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, RelationEntry,
    preprocessed_columns::PreProcessedColumnId,
};

use crate::privacy_pool::poseidon_hash::{
    EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
    apply_external_round_matrix, apply_internal_round_matrix,
};

#[derive(Clone)]
pub struct MerkleMembershipEval {
    pub log_n_rows: u32,
    pub depth: usize,
    pub is_active_id: PreProcessedColumnId,
    pub is_step_id: PreProcessedColumnId,
    pub is_first_id: PreProcessedColumnId,
    pub is_last_id: PreProcessedColumnId,
    pub leaf_relation: crate::privacy_pool::relations::LeafRelation,
    pub root_relation: crate::privacy_pool::relations::RootRelation,
    pub claimed_sum: stwo::core::fields::qm31::SecureField,
}

impl FrameworkEval for MerkleMembershipEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 3 // LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_active_val = eval.get_preprocessed_column(self.is_active_id.clone());
        let is_step_val = eval.get_preprocessed_column(self.is_step_id.clone());
        let is_first_val = eval.get_preprocessed_column(self.is_first_id.clone());
        let is_last_val = eval.get_preprocessed_column(self.is_last_id.clone());

        // Column 0: index_bit
        let [index_bit, index_bit_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);

        // Constraint: index_bit must be 0 or 1
        eval.add_constraint(
            is_active_val.clone() * index_bit.clone() * (index_bit.clone() - E::F::one()),
        );

        // Columns 1-16: initial_state (Poseidon input)
        let [initial_state_first_curr, initial_state_first_next] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
        let [initial_state_second_curr, initial_state_second_next] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);

        // Read the rest of initial_state (cols 3-16)
        let initial_state: [E::F; N_STATE] = std::array::from_fn(|i| {
            if i == 0 {
                initial_state_first_curr.clone()
            } else if i == 1 {
                initial_state_second_curr.clone()
            } else {
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone()
            }
        });

        // Constraint: state[2..16] must be zero (capacity)
        for i in 2..N_STATE {
            eval.add_constraint(is_active_val.clone() * initial_state[i].clone());
        }

        // Poseidon2 permutation constraints
        let mut state = initial_state.clone();

        // Apply initial external round matrix (Poseidon2 standard)
        apply_external_round_matrix(&mut state);

        // First 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            // Add round constants
            for i in 0..N_STATE {
                state[i] = state[i].clone() + E::F::from(EXTERNAL_ROUND_CONSTS[round][i]);
            }
            let initial_state_round = state.clone();

            // Step 1: Square the state (x^2)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask;
            }

            // Step 2: Square again (x^4)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask;
            }

            // Step 3: Multiply by initial state (x^5) and apply external matrix
            state = std::array::from_fn(|i| state[i].clone() * initial_state_round[i].clone());
            apply_external_round_matrix(&mut state);
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
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
            let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
            eval.add_constraint(is_active_val.clone() * (state[0].clone() - mask.clone()));
            state[0] = mask;

            // Step 2: Square again (x^4)
            state[0] = state[0].clone() * state[0].clone();
            let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
            eval.add_constraint(is_active_val.clone() * (state[0].clone() - mask.clone()));
            state[0] = mask;

            // Step 3: Multiply by initial state[0] (x^5)
            state[0] = state[0].clone() * initial_state_0;
            let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
            eval.add_constraint(is_active_val.clone() * (state[0].clone() - mask.clone()));
            state[0] = mask;

            // Step 4: Apply internal round matrix and VERIFY all 16 elements
            apply_internal_round_matrix(&mut state);
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
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
            let initial_state_round = state.clone();

            // Step 1: Square the state (x^2)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask;
            }

            // Step 2: Square again (x^4)
            state = std::array::from_fn(|i| state[i].clone() * state[i].clone());
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask;
            }

            // Step 3: Multiply by initial state (x^5) and apply external matrix
            state = std::array::from_fn(|i| state[i].clone() * initial_state_round[i].clone());
            apply_external_round_matrix(&mut state);
            for i in 0..N_STATE {
                let mask = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
                eval.add_constraint(is_active_val.clone() * (state[i].clone() - mask.clone()));
                state[i] = mask;
            }
        }

        // Chain constraint: next row's initial_state should match current row's hash output
        let chain_constraint = (E::F::one() - index_bit_next.clone())
            * (state[0].clone() - initial_state_first_next)
            + index_bit_next * (state[0].clone() - initial_state_second_next);

        eval.add_constraint(is_step_val * chain_constraint);

        let current_node_value = (E::F::one() - index_bit.clone()) * initial_state[0].clone()
            + index_bit.clone() * initial_state[1].clone();

        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            (-is_first_val.clone()).into(),
            &[current_node_value],
        ));

        let root_value = state[0].clone();
        eval.add_to_relation(RelationEntry::new(
            &self.root_relation,
            is_last_val.into(),
            &[root_value],
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type MerkleMembershipComponent = FrameworkComponent<MerkleMembershipEval>;

pub fn gen_merkle_is_active_column(
    log_size: u32,
    depth: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..depth.min(n_rows) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn gen_merkle_is_step_column(
    log_size: u32,
    depth: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..(depth.saturating_sub(1)).min(n_rows) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn merkle_is_active_column_id(log_size: u32, depth: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("merkle_is_active_{}_{}", log_size, depth),
    }
}

pub fn merkle_is_step_column_id(log_size: u32, depth: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("merkle_is_step_{}_{}", log_size, depth),
    }
}

pub fn gen_merkle_is_first_column(
    log_size: u32,
    _depth: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    // is_first = 1 only for row 0
    if n_rows > 0 {
        col.set(0, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn merkle_is_first_column_id(log_size: u32, depth: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("merkle_is_first_{}_{}", log_size, depth),
    }
}

pub fn gen_merkle_is_last_column(
    log_size: u32,
    depth: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    if depth > 0 && depth - 1 < n_rows {
        col.set(depth - 1, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn merkle_is_last_column_id(log_size: u32, depth: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("merkle_is_last_{}_{}", log_size, depth),
    }
}
