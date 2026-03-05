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

use super::types::{ChainInputs, ChainOutputs};
use crate::privacy_pool::poseidon_hash::{
    EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
    apply_external_round_matrix, apply_internal_round_matrix,
};

pub type ColumnVec<T> = Vec<T>;

pub const N_CHAIN_ROWS: usize = 3;

pub const N_COLUMNS: usize = N_STATE // initial_state
    + (N_HALF_FULL_ROUNDS * 3 * N_STATE) // first_half_full_rounds
    + (N_PARTIAL_ROUNDS * (3 + N_STATE)) // partial_rounds: 3 S-box steps + 16 after matrix
    + (N_HALF_FULL_ROUNDS * 3 * N_STATE); // second_half_full_rounds

pub fn gen_poseidon_chain_trace(
    log_size: u32,
    inputs: ChainInputs,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ChainOutputs,
) {
    let n_rows = 1 << log_size;
    assert!(n_rows >= N_CHAIN_ROWS, "log_size too small for chain");

    let mut trace = (0..N_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect::<Vec<_>>();

    let hash1 = fill_poseidon_row(&mut trace, 0, inputs.input1_a, inputs.input1_b);
    let hash2 = fill_poseidon_row(&mut trace, 1, hash1, inputs.input2);
    let leaf = fill_poseidon_row(&mut trace, 2, hash2, inputs.input3);

    for row in N_CHAIN_ROWS..n_rows {
        for col_index in 0..N_COLUMNS {
            trace[col_index].set(row, BaseField::from_u32_unchecked(0));
        }
    }

    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    let trace_cols = trace
        .into_iter()
        .map(|col| CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col))
        .collect::<Vec<_>>();

    (
        trace_cols,
        ChainOutputs {
            secret_nullifier_hash: hash1,
            secret_nullifier_amount_hash: hash2,
            leaf,
        },
    )
}

pub fn fill_poseidon_row(
    trace: &mut Vec<Col<SimdBackend, BaseField>>,
    row: usize,
    input1: BaseField,
    input2: BaseField,
) -> BaseField {
    let mut col_index = 0;
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = input1;
    state[1] = input2;

    // Write initial_state
    for i in 0..N_STATE {
        trace[col_index].set(row, state[i]);
        col_index += 1;
    }

    // Apply initial external round matrix
    apply_external_round_matrix(&mut state);

    // First 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        // Add round constants
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round][i];
        }
        let initial_state = state;

        // Step 1: Square the state (x^2) and write to trace
        state = std::array::from_fn(|i| {
            let squared = state[i] * state[i];
            squared
        });
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // Step 2: Square again (x^4) and write to trace
        state = std::array::from_fn(|i| {
            let squared = state[i] * state[i];
            squared
        });
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // Step 3: Multiply by initial state (x^5) and apply external matrix
        state = std::array::from_fn(|i| state[i] * initial_state[i]);
        apply_external_round_matrix(&mut state);
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }
    }

    // Partial rounds
    for round in 0..N_PARTIAL_ROUNDS {
        // Add round constant (only to first element)
        state[0] = state[0] + INTERNAL_ROUND_CONSTS[round];
        let initial_state_0 = state[0];

        // Step 1: Square the first element (x^2) and write to trace
        state[0] = state[0] * state[0];
        trace[col_index].set(row, state[0]);
        col_index += 1;

        // Step 2: Square again (x^4) and write to trace
        state[0] = state[0] * state[0];
        trace[col_index].set(row, state[0]);
        col_index += 1;

        // Step 3: Multiply by initial state[0] (x^5) and write to trace
        state[0] = state[0] * initial_state_0;
        trace[col_index].set(row, state[0]);
        col_index += 1;

        // Step 4: Apply internal round matrix and write ALL 16 elements to trace
        apply_internal_round_matrix(&mut state);
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }
    }

    // Last 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        // Add round constants
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
        }
        let initial_state = state;

        // Step 1: Square the state (x^2) and write to trace
        state = std::array::from_fn(|i| {
            let squared = state[i] * state[i];
            squared
        });
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // Step 2: Square again (x^4) and write to trace
        state = std::array::from_fn(|i| {
            let squared = state[i] * state[i];
            squared
        });
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // Step 3: Multiply by initial state (x^5) and apply external matrix
        state = std::array::from_fn(|i| state[i] * initial_state[i]);
        apply_external_round_matrix(&mut state);
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }
    }

    state[0]
}
