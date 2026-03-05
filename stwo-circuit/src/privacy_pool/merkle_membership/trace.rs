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

use super::types::MerkleInputs;
use crate::privacy_pool::poseidon_hash::{
    EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
    apply_external_round_matrix, apply_internal_round_matrix,
};

pub type ColumnVec<T> = Vec<T>;

const N_POSEIDON_COLUMNS: usize = N_STATE // initial_state
    + (N_HALF_FULL_ROUNDS * 3 * N_STATE) // first_half_full_rounds
    + (N_PARTIAL_ROUNDS * (3 + N_STATE)) // partial_rounds: 3 S-box steps + 16 after matrix
    + (N_HALF_FULL_ROUNDS * 3 * N_STATE); // second_half_full_rounds

pub const N_COLUMNS: usize = 1 + N_POSEIDON_COLUMNS;

pub fn gen_merkle_trace(
    log_size: u32,
    inputs: &MerkleInputs,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    BaseField,
) {
    let depth = inputs.depth();
    let n_rows = 1 << log_size;

    assert!(
        depth > 0,
        "Merkle tree depth must be at least 1 (got depth={})",
        depth
    );
    assert!(
        depth <= n_rows,
        "Tree depth {} exceeds trace size {}",
        depth,
        n_rows
    );
    assert!(
        (inputs.index as usize) < (1 << depth),
        "Leaf index {} is out of bounds for tree depth {} (max index: {})",
        inputs.index,
        depth,
        (1 << depth) - 1
    );

    let mut trace = (0..N_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect::<Vec<_>>();

    let mut current_node = inputs.leaf;
    let mut computed_root = BaseField::from_u32_unchecked(0);

    for row in 0..n_rows {
        let is_active_row = row < depth;

        if !is_active_row {
            // Padding row: all zeros
            for col in trace.iter_mut() {
                col.set(row, BaseField::from_u32_unchecked(0));
            }
        } else {
            // Active row: compute one level of the Merkle path
            let level = row;
            let index_bit = (inputs.index >> level) & 1;
            let sibling = inputs.siblings[level];

            // Column 0: Store index_bit (used for dynamic chain constraint and LogUp)
            trace[0].set(row, BaseField::from_u32_unchecked(index_bit as u32));

            // Determine left and right children based on index bit
            let (left_child, right_child) = if index_bit == 0 {
                (current_node, sibling)
            } else {
                (sibling, current_node)
            };

            // Fill the row with Poseidon2 permutation (columns 1-174)
            let hash_result = fill_merkle_row(&mut trace[1..], row, left_child, right_child);

            current_node = hash_result;

            // Save computed root from the last active row
            if row == depth - 1 {
                computed_root = hash_result;
            }
        }
    }

    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace_evals = trace
        .into_iter()
        .map(|eval| CircleEvaluation::new(domain, eval))
        .collect();

    (trace_evals, computed_root)
}

fn fill_merkle_row(
    trace: &mut [Col<SimdBackend, BaseField>],
    row: usize,
    left: BaseField,
    right: BaseField,
) -> BaseField {
    let mut col_index = 0;

    // Initialize state: [left, right, 0, 0, ..., 0]
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = left;
    state[1] = right;

    // Write initial_state (16 columns)
    for i in 0..N_STATE {
        trace[col_index].set(row, state[i]);
        col_index += 1;
    }

    // Apply initial external round matrix (Poseidon2 standard)
    apply_external_round_matrix(&mut state);

    // First 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        // Add round constants
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round][i];
        }
        let initial_state = state;

        // Step 1: Square the state (x^2) and write to trace
        state = std::array::from_fn(|i| state[i] * state[i]);
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // Step 2: Square again (x^4) and write to trace
        state = std::array::from_fn(|i| state[i] * state[i]);
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
        state = std::array::from_fn(|i| state[i] * state[i]);
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // Step 2: Square again (x^4) and write to trace
        state = std::array::from_fn(|i| state[i] * state[i]);
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
