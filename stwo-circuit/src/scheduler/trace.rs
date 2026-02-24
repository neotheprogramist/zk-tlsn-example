use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

pub fn gen_scheduler_trace(
    log_size: u32,
    computed_root: BaseField,
    expected_root: BaseField,
    commitment_amount: BaseField,
    refund_amount: BaseField,
    deposit_leaf: BaseField,
    refund_leaf: BaseField,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1 << log_size;
    let commitment_u32 = commitment_amount.0;
    let refund_u32 = refund_amount.0;
    assert!(
        commitment_u32 >= refund_u32,
        "🚨 SECURITY: Amount underflow detected! commitment_amount ({}) < refund_amount ({}). \
         This would allow withdrawing more funds than deposited.",
        commitment_u32,
        refund_u32
    );

    let mut trace = vec![
        Col::<SimdBackend, BaseField>::zeros(n_rows),
        Col::<SimdBackend, BaseField>::zeros(n_rows),
        Col::<SimdBackend, BaseField>::zeros(n_rows),
        Col::<SimdBackend, BaseField>::zeros(n_rows),
        Col::<SimdBackend, BaseField>::zeros(n_rows),
        Col::<SimdBackend, BaseField>::zeros(n_rows),
    ];

    if n_rows > 0 {
        trace[0].set(0, computed_root);
        trace[1].set(0, expected_root);
        trace[2].set(0, commitment_amount);
        trace[3].set(0, refund_amount);
        trace[4].set(0, deposit_leaf);
        trace[5].set(0, refund_leaf);
    }

    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    trace
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}
