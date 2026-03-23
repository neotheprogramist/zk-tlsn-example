use stwo::core::fields::{m31::BaseField, qm31::SecureField};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry,
    preprocessed_columns::PreProcessedColumnId,
};

use crate::privacy_pool::relations::{LeafRelation, RootRelation};

#[derive(Clone)]
pub struct OfferSchedulerEval {
    pub log_n_rows: u32,
    pub is_first_id: PreProcessedColumnId,
    pub leaf_relation: LeafRelation,
    pub root_relation: RootRelation,
    pub offer_amount: BaseField,
    pub offer_commitment: BaseField,
    pub refund_commitment_hash: BaseField,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for OfferSchedulerEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 3
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(self.is_first_id.clone());

        let computed_root = eval.next_trace_mask();
        let expected_root = eval.next_trace_mask();
        let deposit_amount = eval.next_trace_mask();
        let offer_amount = eval.next_trace_mask();
        let refund_amount = eval.next_trace_mask();
        let deposit_leaf = eval.next_trace_mask();
        let offer_leaf = eval.next_trace_mask();
        let refund_leaf = eval.next_trace_mask();

        eval.add_constraint(is_first.clone() * (computed_root.clone() - expected_root));

        eval.add_constraint(
            is_first.clone() * (deposit_amount - offer_amount.clone() - refund_amount),
        );

        eval.add_constraint(
            is_first.clone() * (E::F::from(self.offer_amount) - offer_amount),
        );

        eval.add_constraint(
            is_first.clone() * (E::F::from(self.offer_commitment) - offer_leaf.clone()),
        );

        eval.add_constraint(
            is_first.clone() * (E::F::from(self.refund_commitment_hash) - refund_leaf.clone()),
        );

        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            (-is_first.clone()).into(),
            &[deposit_leaf],
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.root_relation,
            (-is_first.clone()).into(),
            &[computed_root],
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            (-is_first).into(),
            &[refund_leaf],
        ));

        // NOTE: offer_leaf is NOT added to LogUp (goes to offersTree, not main tree)
        // Only refund_leaf is in LogUp because it goes back to the main tree

        eval.finalize_logup();
        eval
    }
}

pub type OfferSchedulerComponent = FrameworkComponent<OfferSchedulerEval>;
