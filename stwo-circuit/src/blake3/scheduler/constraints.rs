use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};

use itertools::{Itertools, chain};
use num_traits::{One, Zero};
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::blake3::blake3::MSG_SCHEDULE;

use super::BlakeElements;
use crate::blake3::round::RoundElements;
use crate::blake3::{BlakeXorElements, Fu32, N_ROUNDS, STATE_SIZE};

const BYTE_SPLIT: BaseField = BaseField::from_u32_unchecked(256);

/// Applies Blake3 MSG_SCHEDULE permutation `iterations` times to messages
fn apply_blake3_permutation<F>(
    messages: &[Fu32<F>; STATE_SIZE],
    iterations: usize,
) -> [Fu32<F>; STATE_SIZE]
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    let mut result = messages.clone();
    for _ in 0..iterations {
        let permuted = MSG_SCHEDULE.map(|i| result[i as usize].clone());
        result = permuted;
    }
    result
}

pub fn eval_blake_scheduler_constraints<E: EvalAtRow>(
    eval: &mut E,
    blake_lookup_elements: &BlakeElements,
    round_lookup_elements: &RoundElements,
    xor_elements: &BlakeXorElements,
    committed_hash_words: [u32; 8],
) {
    let messages: [Fu32<E::F>; STATE_SIZE] = std::array::from_fn(|_| eval_next_u32(eval));
    let states: [[Fu32<E::F>; STATE_SIZE]; N_ROUNDS + 1] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval_next_u32(eval)));

    // Schedule.
    for [i, j] in (0..N_ROUNDS).array_chunks::<2>() {
        let [elems_i, elems_j] = [i, j].map(|idx| {
            let input_state = &states[idx];
            let output_state = &states[idx + 1];
            let round_messages = apply_blake3_permutation(&messages, idx);
            chain![
                input_state.iter().cloned().flat_map(Fu32::into_felts),
                output_state.iter().cloned().flat_map(Fu32::into_felts),
                round_messages.iter().cloned().flat_map(Fu32::into_felts)
            ]
            .collect_vec()
        });
        eval.add_to_relation(RelationEntry::new(
            round_lookup_elements,
            E::EF::one(),
            &elems_i,
        ));
        eval.add_to_relation(RelationEntry::new(
            round_lookup_elements,
            E::EF::one(),
            &elems_j,
        ));
    }

    let input_state = &states[0];
    let output_state = &states[N_ROUNDS];

    if N_ROUNDS % 2 == 1 {
        let last_round_idx = N_ROUNDS - 1;
        let last_round_input = &states[last_round_idx];
        let last_round_output = &states[last_round_idx + 1];
        let last_round_messages = apply_blake3_permutation(&messages, last_round_idx);

        eval.add_to_relation(RelationEntry::new(
            round_lookup_elements,
            E::EF::one(),
            &chain![
                last_round_input.iter().cloned().flat_map(Fu32::into_felts),
                last_round_output.iter().cloned().flat_map(Fu32::into_felts),
                last_round_messages
                    .iter()
                    .cloned()
                    .flat_map(Fu32::into_felts)
            ]
            .collect_vec(),
        ));
    }

    // Blake lookup
    eval.add_to_relation(RelationEntry::new(
        blake_lookup_elements,
        E::EF::zero(),
        &chain![
            input_state.iter().cloned().flat_map(Fu32::into_felts),
            output_state.iter().cloned().flat_map(Fu32::into_felts),
            messages.iter().cloned().flat_map(Fu32::into_felts)
        ]
        .collect_vec(),
    ));

    // Output hash constraint: for each output word i,
    // verify that v_final[i] XOR v_final[i+8] == committed_hash_words[i]
    // by decomposing each 16-bit half into bytes and checking via xor8 table.
    for word_i in 0..8usize {
        let a = &output_state[word_i];
        let b = &output_state[word_i + 8];

        let c_word = committed_hash_words[word_i];
        // c bytes (constants in the circuit)
        let c_ll = E::F::from(BaseField::from_u32_unchecked(c_word & 0xFF));
        let c_lh = E::F::from(BaseField::from_u32_unchecked((c_word >> 8) & 0xFF));
        let c_hl = E::F::from(BaseField::from_u32_unchecked((c_word >> 16) & 0xFF));
        let c_hh = E::F::from(BaseField::from_u32_unchecked(c_word >> 24));

        // Read byte splits from trace (8 columns per word: a_ll, b_ll, a_lh, b_lh, a_hl, b_hl, a_hh, b_hh)
        let a_ll = eval.next_trace_mask();
        let b_ll = eval.next_trace_mask();
        let a_lh = eval.next_trace_mask();
        let b_lh = eval.next_trace_mask();
        let a_hl = eval.next_trace_mask();
        let b_hl = eval.next_trace_mask();
        let a_hh = eval.next_trace_mask();
        let b_hh = eval.next_trace_mask();

        // Decomposition constraints: enforce byte splits are correct
        eval.add_constraint(
            a.l.clone() - a_ll.clone() - a_lh.clone() * E::F::from(BYTE_SPLIT),
        );
        eval.add_constraint(
            a.h.clone() - a_hl.clone() - a_hh.clone() * E::F::from(BYTE_SPLIT),
        );
        eval.add_constraint(
            b.l.clone() - b_ll.clone() - b_lh.clone() * E::F::from(BYTE_SPLIT),
        );
        eval.add_constraint(
            b.h.clone() - b_hl.clone() - b_hh.clone() * E::F::from(BYTE_SPLIT),
        );

        // XOR8 logup lookups (batched in pairs by finalize_logup_in_pairs):
        // pair 0: (a_ll, b_ll, c_ll) and (a_lh, b_lh, c_lh)
        eval.add_to_relation(RelationEntry::new(
            &xor_elements.xor8,
            E::EF::one(),
            &[a_ll.clone(), b_ll.clone(), c_ll],
        ));
        eval.add_to_relation(RelationEntry::new(
            &xor_elements.xor8,
            E::EF::one(),
            &[a_lh.clone(), b_lh.clone(), c_lh],
        ));
        // pair 1: (a_hl, b_hl, c_hl) and (a_hh, b_hh, c_hh)
        eval.add_to_relation(RelationEntry::new(
            &xor_elements.xor8,
            E::EF::one(),
            &[a_hl.clone(), b_hl.clone(), c_hl],
        ));
        eval.add_to_relation(RelationEntry::new(
            &xor_elements.xor8,
            E::EF::one(),
            &[a_hh.clone(), b_hh.clone(), c_hh],
        ));
    }

    eval.finalize_logup_in_pairs();
}

fn eval_next_u32<E: EvalAtRow>(eval: &mut E) -> Fu32<E::F> {
    let l = eval.next_trace_mask();
    let h = eval.next_trace_mask();
    Fu32 { l, h }
}
