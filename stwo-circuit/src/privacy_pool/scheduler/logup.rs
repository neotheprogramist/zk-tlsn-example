use num_traits::One;
use stwo::{
    core::{
        ColumnVec,
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

use crate::privacy_pool::relations::{LeafRelation, RootRelation};

pub fn gen_scheduler_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    leaf_relation: &LeafRelation,
    root_relation: &RootRelation,
    log_size: u32,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;

    let mut is_first_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    is_first_col.set(0, BaseField::one());
    bit_reverse_coset_to_circle_domain_order(is_first_col.as_mut_slice());

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let col_data = &trace[4].data;
            let deposit_leaf_value: PackedSecureField = col_data[vec_row].into();

            let denom: PackedSecureField = leaf_relation.combine(&[deposit_leaf_value]);

            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure;

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let col_data = &trace[0].data;
            let computed_root_value: PackedSecureField = col_data[vec_row].into();

            let denom: PackedSecureField = root_relation.combine(&[computed_root_value]);

            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure;

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let col_data = &trace[5].data;
            let refund_leaf_value: PackedSecureField = col_data[vec_row].into();

            let denom: PackedSecureField = leaf_relation.combine(&[refund_leaf_value]);

            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure;

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}
