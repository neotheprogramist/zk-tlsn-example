use num_traits::One;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        utils::bit_reverse_coset_to_circle_domain_order,
    },
    prover::{
        backend::{
            Col, Column,
            simd::{SimdBackend, m31::LOG_N_LANES, qm31::PackedSecureField},
        },
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use super::trace::{ColumnVec, N_CHAIN_ROWS};
use crate::privacy_pool::relations::LeafRelation;
const FINAL_STATE_0_COL: usize = 650;

pub fn gen_poseidon_chain_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    leaf_relation: &LeafRelation,
    log_size: u32,
    leaf_multiplicity: u32,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;

    // Generate is_last selector column (1 only for row N_CHAIN_ROWS-1)
    let mut is_last_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    if N_CHAIN_ROWS > 0 && N_CHAIN_ROWS - 1 < n_rows {
        is_last_col.set(N_CHAIN_ROWS - 1, BaseField::one());
    }
    bit_reverse_coset_to_circle_domain_order(is_last_col.as_mut_slice());

    // Extract leaf value from final_state[0] column (column 426)
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read final_state[0] (leaf value) from column 426
            let col_data = &trace[FINAL_STATE_0_COL].data;
            let leaf_value: PackedSecureField = col_data[vec_row].into();

            // Multiplicity controlled by is_last selector (positive for "yield")
            let is_last_value = is_last_col.data[vec_row];
            let is_last_secure: PackedSecureField = is_last_value.into();

            // Combine using leaf_relation (1 element)
            let denom: PackedSecureField = leaf_relation.combine(&[leaf_value]);

            // Apply multiplicity (2 for deposit chain, 1 for refund chain)
            let multiplicity_base = BaseField::from_u32_unchecked(leaf_multiplicity);
            let multiplicity_packed: stwo::prover::backend::simd::m31::PackedM31 =
                multiplicity_base.into();
            let multiplicity_secure: PackedSecureField = multiplicity_packed.into();
            let numerator = is_last_secure * multiplicity_secure; // +multiplicity for last row

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}
