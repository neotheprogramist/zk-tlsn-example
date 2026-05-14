//! Poseidon2-M31 (<https://eprint.iacr.org/2023/323.pdf>) implemented over
//! `circuits::ops`. The same algebra runs host-side (`*_host`) and
//! in-circuit (`*_in_circuit`) so every cm/nf/auth check is bit-identical
//! across the JS host, the Rust verifier, and the STARK proof.
//!
//! Round constants are toy placeholders — distinct M31-safe values per
//! `(round, index)`. Production needs the proper Poseidon2-M31 constants.

use circuits::{
    context::{Context, TraceContext, Var},
    ivalue::IValue,
    ops::{add, eq, guess, mul},
};
use stwo::core::fields::{m31::M31, qm31::QM31};

pub const N_STATE: usize = 16;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;

/// Sponge rate (M31 elements absorbed per permute).
pub const RATE: usize = 8;
/// Sponge capacity.
pub const CAPACITY: usize = 8;

const fn gen_ext_rc() -> [[u32; N_STATE]; FULL_ROUNDS] {
    let mut out = [[0u32; N_STATE]; FULL_ROUNDS];
    let mut r = 0;
    while r < FULL_ROUNDS {
        let mut i = 0;
        while i < N_STATE {
            // Toy formula: distinct M31-safe values per (r, i).
            let v = ((r as u32) * 0x101 + (i as u32) * 0x11 + 1) * 0x401 + 0x42;
            out[r][i] = v & 0x7FFF_FFFF;
            i += 1;
        }
        r += 1;
    }
    out
}

const fn gen_int_rc() -> [u32; N_PARTIAL_ROUNDS] {
    let mut out = [0u32; N_PARTIAL_ROUNDS];
    let mut r = 0;
    while r < N_PARTIAL_ROUNDS {
        // Use a u64 intermediate, then mask back to M31-safe u32.
        let v = ((r as u64) * 0x10001 + 1) * 0x10101 + 0xCAFE;
        out[r] = (v & 0x7FFF_FFFF) as u32;
        r += 1;
    }
    out
}

const EXT_RC_U32: [[u32; N_STATE]; FULL_ROUNDS] = gen_ext_rc();
const INT_RC_U32: [u32; N_PARTIAL_ROUNDS] = gen_int_rc();

#[inline]
fn pow5_host(x: M31) -> M31 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

fn apply_m4_host(x: [M31; 4]) -> [M31; 4] {
    let t0 = x[0] + x[1];
    let t02 = t0 + t0;
    let t1 = x[2] + x[3];
    let t12 = t1 + t1;
    let t2 = x[1] + x[1] + t1;
    let t3 = x[3] + x[3] + t0;
    let t4 = t12 + t12 + t3;
    let t5 = t02 + t02 + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    [t6, t5, t7, t4]
}

fn apply_external_matrix_host(state: &mut [M31; N_STATE]) {
    for chunk in state.chunks_mut(4) {
        let m4_out = apply_m4_host([chunk[0], chunk[1], chunk[2], chunk[3]]);
        chunk.copy_from_slice(&m4_out);
    }
    for j in 0..4 {
        let s = state[j] + state[j + 4] + state[j + 8] + state[j + 12];
        for i in 0..4 {
            state[4 * i + j] += s;
        }
    }
}

fn apply_internal_matrix_host(state: &mut [M31; N_STATE]) {
    let sum: M31 = state.iter().copied().sum();
    for (i, s) in state.iter_mut().enumerate() {
        *s = *s * M31::from(1u32 << (i + 1)) + sum;
    }
}

fn full_round_host(state: &mut [M31; N_STATE], rc: &[u32; N_STATE]) {
    for (s, c) in state.iter_mut().zip(rc.iter()) {
        *s += M31::from(*c);
    }
    apply_external_matrix_host(state);
    for s in state.iter_mut() {
        *s = pow5_host(*s);
    }
}

pub fn permute_host(state: &mut [M31; N_STATE]) {
    for rc in EXT_RC_U32.iter().take(N_HALF_FULL_ROUNDS) {
        full_round_host(state, rc);
    }
    for rc in INT_RC_U32.iter() {
        state[0] += M31::from(*rc);
        apply_internal_matrix_host(state);
        state[0] = pow5_host(state[0]);
    }
    for rc in EXT_RC_U32.iter().skip(N_HALF_FULL_ROUNDS) {
        full_round_host(state, rc);
    }
}

/// Sponge: absorb `inputs` (one M31 per limb) RATE elements at a time
/// (adding into the first `RATE` state positions), permute after each
/// chunk; finally squeeze the first `RATE` state elements as the hash.
pub fn hash_host(inputs: &[M31]) -> [M31; RATE] {
    let mut state = [M31::from(0u32); N_STATE];
    if inputs.is_empty() {
        permute_host(&mut state);
    } else {
        for chunk in inputs.chunks(RATE) {
            for (s, v) in state.iter_mut().zip(chunk.iter()) {
                *s += *v;
            }
            permute_host(&mut state);
        }
    }
    let mut out = [M31::from(0u32); RATE];
    out.copy_from_slice(&state[..RATE]);
    out
}

/// Convenience: hash a domain-tagged byte sequence. Each byte becomes
/// one M31 limb (lower 31 bits used; values 0..255 are trivially M31-safe).
pub fn hash_domain_bytes_host(domain: u32, parts: &[&[u8]]) -> [M31; RATE] {
    let mut limbs = Vec::with_capacity(1 + parts.iter().map(|p| p.len()).sum::<usize>());
    limbs.push(M31::from(domain));
    for p in parts {
        for &b in *p {
            limbs.push(M31::from(b as u32));
        }
    }
    hash_host(&limbs)
}

/// In-circuit `x → x^5` via three multiplications.
fn pow5_in_circuit<V: IValue>(ctx: &mut Context<V>, x: Var) -> Var {
    let x2 = mul(ctx, x, x);
    let x4 = mul(ctx, x2, x2);
    mul(ctx, x4, x)
}

fn apply_m4_in_circuit<V: IValue>(ctx: &mut Context<V>, x: [Var; 4]) -> [Var; 4] {
    let t0 = add(ctx, x[0], x[1]);
    let t02 = add(ctx, t0, t0);
    let t1 = add(ctx, x[2], x[3]);
    let t12 = add(ctx, t1, t1);
    let two_x1 = add(ctx, x[1], x[1]);
    let t2 = add(ctx, two_x1, t1);
    let two_x3 = add(ctx, x[3], x[3]);
    let t3 = add(ctx, two_x3, t0);
    let two_t12 = add(ctx, t12, t12);
    let t4 = add(ctx, two_t12, t3);
    let two_t02 = add(ctx, t02, t02);
    let t5 = add(ctx, two_t02, t2);
    let t6 = add(ctx, t3, t5);
    let t7 = add(ctx, t2, t4);
    [t6, t5, t7, t4]
}

fn apply_external_matrix_in_circuit<V: IValue>(ctx: &mut Context<V>, state: &mut [Var; N_STATE]) {
    for i in 0..4 {
        let m4_out = apply_m4_in_circuit(
            ctx,
            [
                state[4 * i],
                state[4 * i + 1],
                state[4 * i + 2],
                state[4 * i + 3],
            ],
        );
        state[4 * i..4 * i + 4].copy_from_slice(&m4_out);
    }
    for j in 0..4 {
        let s01 = add(ctx, state[j], state[j + 4]);
        let s23 = add(ctx, state[j + 8], state[j + 12]);
        let s = add(ctx, s01, s23);
        for i in 0..4 {
            state[4 * i + j] = add(ctx, state[4 * i + j], s);
        }
    }
}

fn apply_internal_matrix_in_circuit<V: IValue>(ctx: &mut Context<V>, state: &mut [Var; N_STATE]) {
    let sum = state
        .iter()
        .skip(1)
        .fold(state[0], |acc, s| add(ctx, acc, *s));
    for (i, s) in state.iter_mut().enumerate() {
        let factor_var = ctx.constant(QM31::from(M31::from(1u32 << (i + 1))));
        let scaled = mul(ctx, *s, factor_var);
        *s = add(ctx, scaled, sum);
    }
}

fn full_round_in_circuit<V: IValue>(
    ctx: &mut Context<V>,
    state: &mut [Var; N_STATE],
    rc: &[u32; N_STATE],
) {
    for (s, c) in state.iter_mut().zip(rc.iter()) {
        let rc_var = ctx.constant(QM31::from(M31::from(*c)));
        *s = add(ctx, *s, rc_var);
    }
    apply_external_matrix_in_circuit(ctx, state);
    for s in state.iter_mut() {
        *s = pow5_in_circuit(ctx, *s);
    }
}

/// One full Poseidon2-M31 permutation expressed as STARK constraints
/// over the supplied `state` vars.
pub fn permute_in_circuit<V: IValue>(ctx: &mut Context<V>, state: &mut [Var; N_STATE]) {
    for rc in EXT_RC_U32.iter().take(N_HALF_FULL_ROUNDS) {
        full_round_in_circuit(ctx, state, rc);
    }
    for rc in INT_RC_U32.iter() {
        let rc_var = ctx.constant(QM31::from(M31::from(*rc)));
        state[0] = add(ctx, state[0], rc_var);
        apply_internal_matrix_in_circuit(ctx, state);
        state[0] = pow5_in_circuit(ctx, state[0]);
    }
    for rc in EXT_RC_U32.iter().skip(N_HALF_FULL_ROUNDS) {
        full_round_in_circuit(ctx, state, rc);
    }
}

/// In-circuit sponge over already-guessed witness variables. Returns
/// the first `RATE` state elements as the hash output (Var form).
pub fn hash_in_circuit(ctx: &mut TraceContext, inputs: &[Var]) -> [Var; RATE] {
    let zero = ctx.zero();
    let mut state: [Var; N_STATE] = [zero; N_STATE];
    if inputs.is_empty() {
        permute_in_circuit(ctx, &mut state);
    } else {
        for chunk in inputs.chunks(RATE) {
            for i in 0..chunk.len() {
                state[i] = add(ctx, state[i], chunk[i]);
            }
            permute_in_circuit(ctx, &mut state);
        }
    }
    let mut out = [zero; RATE];
    out[..RATE].copy_from_slice(&state[..RATE]);
    out
}

/// Adds one dummy blake gate so the stwo prover's blake sub-components
/// (`blake_output`, `triple_xor_32`, …) have ≥ 1 input — they assert
/// non-empty during `write_trace`. Required because every vault leaf
/// hashes via Poseidon and doesn't naturally emit any blake gate.
pub fn prime_blake_component(ctx: &mut TraceContext) {
    let zero = ctx.zero();
    let _ = circuits::blake::blake(ctx, &[zero], 16);
}

/// Bind an in-circuit hash output to a host-known expected value.
///
/// For each of the `RATE` output limbs, guess the expected value and
/// constrain `computed == expected`. The caller supplies the expected
/// hash (typically pre-computed via `hash_host`).
pub fn bind_hash_to_expected(
    ctx: &mut TraceContext,
    computed: &[Var; RATE],
    expected: &[M31; RATE],
) {
    for i in 0..RATE {
        let expected_var = guess(ctx, QM31::from(expected[i]));
        eq(ctx, computed[i], expected_var);
    }
}

/// Guess a sequence of M31 limbs as witness variables. Helper for the
/// leaf-circuit builders.
pub fn guess_limbs(ctx: &mut TraceContext, values: &[M31]) -> Vec<Var> {
    values.iter().map(|&v| guess(ctx, QM31::from(v))).collect()
}

/// Convert a byte sequence to M31 limbs — one byte per limb (lower 8
/// bits used). Trivially M31-safe; the simplest packing.
pub fn bytes_to_limbs(bytes: &[u8]) -> Vec<M31> {
    bytes.iter().map(|&b| M31::from(b as u32)).collect()
}

/// Convert RATE M31 limbs back to a 32-byte hash output.
/// Each limb's low 8 bits become one output byte (4 bytes per limb,
/// little-endian, mod 2^32).
pub fn limbs_to_bytes_32(limbs: &[M31; RATE]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let v = limb.0;
        out[4 * i] = (v & 0xff) as u8;
        out[4 * i + 1] = ((v >> 8) & 0xff) as u8;
        out[4 * i + 2] = ((v >> 16) & 0xff) as u8;
        out[4 * i + 3] = ((v >> 24) & 0xff) as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permute_host_deterministic() {
        let mut s1 = [M31::from(0u32); N_STATE];
        let mut s2 = [M31::from(0u32); N_STATE];
        permute_host(&mut s1);
        permute_host(&mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn distinct_inputs_distinct_outputs() {
        let a = hash_host(&[M31::from(1u32)]);
        let b = hash_host(&[M31::from(2u32)]);
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separation_distinguishes_inputs() {
        let with_d1 = hash_domain_bytes_host(1, &[b"hello"]);
        let with_d2 = hash_domain_bytes_host(2, &[b"hello"]);
        assert_ne!(with_d1, with_d2);
    }
}
