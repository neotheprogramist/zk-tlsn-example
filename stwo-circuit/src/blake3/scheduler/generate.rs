use std::simd::u32x16;

use itertools::{Itertools, chain};
use num_traits::Zero;
use stwo::core::ColumnVec;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::Column;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_constraint_framework::{LogupTraceGenerator, Relation};
use tracing::{Level, span};

use super::BlakeElements;
use crate::blake3::blake3::{self, MSG_SCHEDULE};
use crate::blake3::round::{BlakeRoundInput, RoundElements};
use crate::blake3::{BlakeXorElements, N_ROUND_INPUT_FELTS, N_ROUNDS, STATE_SIZE, XorAccums, to_felts};

#[derive(Copy, Clone, Default)]
pub struct BlakeInput {
    pub v: [u32x16; STATE_SIZE],
    pub m: [u32x16; STATE_SIZE],
}

#[derive(Clone)]
pub struct BlakeSchedulerLookupData {
    pub round_lookups: [[BaseColumn; N_ROUND_INPUT_FELTS]; N_ROUNDS],
    pub blake_lookups: [BaseColumn; N_ROUND_INPUT_FELTS],
    /// 8 output words × 4 byte positions × 2 sides (a=v_final[i], b=v_final[i+8])
    pub output_xor_data: [[[BaseColumn; 2]; 4]; 8],
}
impl BlakeSchedulerLookupData {
    fn new(log_size: u32) -> Self {
        Self {
            round_lookups: std::array::from_fn(|_| {
                std::array::from_fn(|_| unsafe { BaseColumn::uninitialized(1 << log_size) })
            }),
            blake_lookups: std::array::from_fn(|_| unsafe {
                BaseColumn::uninitialized(1 << log_size)
            }),
            output_xor_data: std::array::from_fn(|_| {
                std::array::from_fn(|_| {
                    std::array::from_fn(|_| unsafe { BaseColumn::uninitialized(1 << log_size) })
                })
            }),
        }
    }
}

pub fn prepare_blake_input_from_bytes(x: &[u8], blinder: &[u8; 16]) -> BlakeInput {
    let input_len = x.len() + 16;
    assert!(input_len <= 64, "input too large for single Blake3 block");

    let mut padded = [0u8; 64];
    padded[..x.len()].copy_from_slice(x);
    padded[x.len()..input_len].copy_from_slice(blinder);

    let message: [u32; 16] = std::array::from_fn(|i| {
        u32::from_le_bytes([
            padded[i * 4],
            padded[i * 4 + 1],
            padded[i * 4 + 2],
            padded[i * 4 + 3],
        ])
    });

    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    let mut v = [0u32; 16];
    v[0..8].copy_from_slice(&IV);
    v[8..12].copy_from_slice(&IV[0..4]);
    v[12] = 0;
    v[13] = 0;
    v[14] = input_len as u32;
    v[15] = 0b1011;

    BlakeInput {
        v: v.map(u32x16::splat),
        m: message.map(u32x16::splat),
    }
}

/// Computes the Blake3 output hash for x || blinder.
/// Returns the 32-byte hash as [u8; 32].
pub fn compute_commitment_hash(x: &[u8], blinder: &[u8; 16]) -> [u8; 32] {
    let input = prepare_blake_input_from_bytes(x, blinder);
    let mut v = input.v;
    let mut m_current = input.m;
    for r in 0..N_ROUNDS {
        blake3::round(&mut v, m_current, r);
        m_current = MSG_SCHEDULE.map(|i| m_current[i as usize]);
    }
    let mut hash = [0u8; 32];
    for i in 0..8 {
        let a = v[i].to_array()[0];
        let b = v[i + 8].to_array()[0];
        let word = a ^ b;
        hash[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    hash
}

pub fn gen_trace(
    log_size: u32,
    balance_committed_part: &[u8],
    blinder: [u8; 16],
    xor_accums: &mut XorAccums,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    BlakeSchedulerLookupData,
    Vec<BlakeRoundInput>,
) {
    let blake_input = prepare_blake_input_from_bytes(balance_committed_part, &blinder);
    let inputs = vec![blake_input; 1 << (log_size - LOG_N_LANES)];

    let _span = span!(Level::INFO, "Scheduler Generation").entered();
    let mut lookup_data = BlakeSchedulerLookupData::new(log_size);
    let mut round_inputs = Vec::with_capacity(inputs.len() * N_ROUNDS);

    // 16*2 (messages) + 16*2 (initial_v) + 7*16*2 (v after each round) + 8*8 (output byte splits)
    // = 32 + 32 + 224 + 64 = 352 columns
    let n_cols = STATE_SIZE * 2 + STATE_SIZE * 2 + N_ROUNDS * STATE_SIZE * 2 + 64;

    let mut trace = (0..n_cols)
        .map(|_| unsafe { BaseColumn::uninitialized(1 << log_size) })
        .collect_vec();

    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let mut col_index = 0;

        let mut write_u32_array = |x: [u32x16; STATE_SIZE], col_index: &mut usize| {
            x.iter().for_each(|x| {
                to_felts(x).iter().for_each(|x| {
                    trace[*col_index].data[vec_row] = *x;
                    *col_index += 1;
                });
            });
        };

        let BlakeInput { mut v, m } = inputs.get(vec_row).copied().unwrap_or_default();
        let initial_v = v;

        write_u32_array(m, &mut col_index);
        write_u32_array(v, &mut col_index);

        let mut m_current = m;

        for r in 0..N_ROUNDS {
            let prev_v = v;
            blake3::round(&mut v, m_current, r);
            write_u32_array(v, &mut col_index);

            round_inputs.push(BlakeRoundInput {
                v: prev_v,
                m: m_current,
            });

            chain![
                prev_v.iter().flat_map(to_felts),
                v.iter().flat_map(to_felts),
                m_current.iter().flat_map(to_felts)
            ]
            .enumerate()
            .for_each(|(i, val)| lookup_data.round_lookups[r][i].data[vec_row] = val);

            m_current = MSG_SCHEDULE.map(|i| m_current[i as usize]);
        }

        chain![
            initial_v.iter().flat_map(to_felts),
            v.iter().flat_map(to_felts),
            m.iter().flat_map(to_felts)
        ]
        .enumerate()
        .for_each(|(i, val)| lookup_data.blake_lookups[i].data[vec_row] = val);

        // v is now the final state after N_ROUNDS rounds.
        // Output word i = v[i] XOR v[i+8] for i in 0..8.
        // Write byte splits to trace columns 288..352 and lookup_data.
        for word_i in 0..8usize {
            let a_word = v[word_i].to_array()[0];
            let b_word = v[word_i + 8].to_array()[0];

            let a_l = a_word & 0xFFFF;
            let a_h = a_word >> 16;
            let b_l = b_word & 0xFFFF;
            let b_h = b_word >> 16;

            // byte_pairs[j] = (a_byte_j, b_byte_j)
            let byte_pairs: [(u32, u32); 4] = [
                (a_l & 0xFF,         b_l & 0xFF),
                ((a_l >> 8) & 0xFF,  (b_l >> 8) & 0xFF),
                (a_h & 0xFF,         b_h & 0xFF),
                ((a_h >> 8) & 0xFF,  (b_h >> 8) & 0xFF),
            ];

            for (byte_pos, (a_byte, b_byte)) in byte_pairs.iter().enumerate() {
                let a_packed = unsafe {
                    stwo::prover::backend::simd::m31::PackedBaseField::from_simd_unchecked(
                        u32x16::splat(*a_byte),
                    )
                };
                let b_packed = unsafe {
                    stwo::prover::backend::simd::m31::PackedBaseField::from_simd_unchecked(
                        u32x16::splat(*b_byte),
                    )
                };

                trace[col_index].data[vec_row] = a_packed;
                col_index += 1;
                trace[col_index].data[vec_row] = b_packed;
                col_index += 1;

                lookup_data.output_xor_data[word_i][byte_pos][0].data[vec_row] = a_packed;
                lookup_data.output_xor_data[word_i][byte_pos][1].data[vec_row] = b_packed;

                xor_accums.xor8.add_input(
                    u32x16::splat(*a_byte),
                    u32x16::splat(*b_byte),
                );
            }
        }
    }

    println!(
        "Blake scheduler total vec_rows: {}",
        1 << (log_size - LOG_N_LANES)
    );

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = trace
        .into_iter()
        .map(|eval| CircleEvaluation::new(domain, eval))
        .collect();

    (trace, lookup_data, round_inputs)
}

pub fn gen_interaction_trace(
    log_size: u32,
    lookup_data: BlakeSchedulerLookupData,
    round_lookup_elements: &RoundElements,
    blake_lookup_elements: &BlakeElements,
    xor_elements: &BlakeXorElements,
    committed_hash_words: [u32; 8],
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let _span = span!(Level::INFO, "Generate scheduler interaction trace").entered();

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    // Round pair columns (existing).
    for [l0, l1] in lookup_data.round_lookups.array_chunks::<2>() {
        let mut col_gen = logup_gen.new_col();

        #[allow(clippy::needless_range_loop)]
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let p0: PackedSecureField =
                round_lookup_elements.combine(&l0.each_ref().map(|l| l.data[vec_row]));
            let p1: PackedSecureField =
                round_lookup_elements.combine(&l1.each_ref().map(|l| l.data[vec_row]));
            #[allow(clippy::eq_op)]
            col_gen.write_frac(vec_row, p0 + p1, p0 * p1);
        }

        col_gen.finalize_col();
    }

    // Last pair (round6 + blake).
    {
        let mut col_gen = logup_gen.new_col();
        #[allow(clippy::needless_range_loop)]
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let p_blake: PackedSecureField = blake_lookup_elements.combine(
                &lookup_data
                    .blake_lookups
                    .each_ref()
                    .map(|l| l.data[vec_row]),
            );
            if N_ROUNDS % 2 == 1 {
                let p_round: PackedSecureField = round_lookup_elements.combine(
                    &lookup_data.round_lookups[N_ROUNDS - 1]
                        .each_ref()
                        .map(|l| l.data[vec_row]),
                );
                col_gen.write_frac(vec_row, p_blake, p_round * p_blake);
            } else {
                col_gen.write_frac(vec_row, PackedSecureField::zero(), p_blake);
            }
        }
        col_gen.finalize_col();
    }

    // New: 16 columns for output hash XOR8 verification.
    // Each word produces 2 columns (bytes 0-1 and bytes 2-3).
    for word_i in 0..8usize {
        let c_word = committed_hash_words[word_i];
        let c_bytes: [u32; 4] = [
            c_word & 0xFF,
            (c_word >> 8) & 0xFF,
            (c_word >> 16) & 0xFF,
            c_word >> 24,
        ];

        // Column: byte pair 0 and 1 for word_i.
        {
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let a0 = lookup_data.output_xor_data[word_i][0][0].data[vec_row];
                let b0 = lookup_data.output_xor_data[word_i][0][1].data[vec_row];
                let c0 = unsafe {
                    stwo::prover::backend::simd::m31::PackedBaseField::from_simd_unchecked(
                        u32x16::splat(c_bytes[0]),
                    )
                };
                let a1 = lookup_data.output_xor_data[word_i][1][0].data[vec_row];
                let b1 = lookup_data.output_xor_data[word_i][1][1].data[vec_row];
                let c1 = unsafe {
                    stwo::prover::backend::simd::m31::PackedBaseField::from_simd_unchecked(
                        u32x16::splat(c_bytes[1]),
                    )
                };
                let p0: PackedSecureField = xor_elements.xor8.combine(&[a0, b0, c0]);
                let p1: PackedSecureField = xor_elements.xor8.combine(&[a1, b1, c1]);
                col_gen.write_frac(vec_row, p0 + p1, p0 * p1);
            }
            col_gen.finalize_col();
        }

        // Column: byte pair 2 and 3 for word_i.
        {
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let a2 = lookup_data.output_xor_data[word_i][2][0].data[vec_row];
                let b2 = lookup_data.output_xor_data[word_i][2][1].data[vec_row];
                let c2 = unsafe {
                    stwo::prover::backend::simd::m31::PackedBaseField::from_simd_unchecked(
                        u32x16::splat(c_bytes[2]),
                    )
                };
                let a3 = lookup_data.output_xor_data[word_i][3][0].data[vec_row];
                let b3 = lookup_data.output_xor_data[word_i][3][1].data[vec_row];
                let c3 = unsafe {
                    stwo::prover::backend::simd::m31::PackedBaseField::from_simd_unchecked(
                        u32x16::splat(c_bytes[3]),
                    )
                };
                let p2: PackedSecureField = xor_elements.xor8.combine(&[a2, b2, c2]);
                let p3: PackedSecureField = xor_elements.xor8.combine(&[a3, b3, c3]);
                col_gen.write_frac(vec_row, p2 + p3, p2 * p3);
            }
            col_gen.finalize_col();
        }
    }

    logup_gen.finalize_last()
}
