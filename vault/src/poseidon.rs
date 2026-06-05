//! Poseidon2-M31 (<https://eprint.iacr.org/2023/323.pdf>) implemented over
//! `circuits::ops`. The same algebra runs host-side (`*_host`) and
//! in-circuit (`*_in_circuit`) so every cm/nf/auth check is bit-identical
//! across the JS host, the Rust verifier, and the STARK proof.
//!
//! Round constants and the internal-matrix diagonal are byte-identical to
//! the mpz Poseidon2-M31 instance used by the TLSN MPC-VM hasher
//! (`mpz_circuits::circuits::poseidon2`), so that an MPC-VM transcript
//! commitment opens against an in-circuit `hash_in_circuit` over the same
//! plaintext ‖ blinder bytes.

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

/// Internal-round diagonal matrix coefficients (`diag - 1` form, hence
/// `_M_1`). Copied verbatim from `mpz_circuits::circuits::poseidon2`.
const MAT_INTERNAL_DIAG_M_1: [u32; N_STATE] = [
    0x07b80ac4, 0x6bd9cb33, 0x48ee3f9f, 0x4f63dd19, 0x18c546b3, 0x5af89e8b, 0x4ff23de8, 0x4f78aaf6,
    0x53bdc6d4, 0x5c59823e, 0x2a471c72, 0x4c975e79, 0x58dc64d4, 0x06e9315d, 0x2cf32286, 0x2fb6755d,
];

/// External (full-round) constants. Copied verbatim from
/// `mpz_circuits::circuits::poseidon2`.
const EXT_RC_U32: [[u32; N_STATE]; FULL_ROUNDS] = [
    [
        0x768bab52, 0x70e0ab7d, 0x3d266c8a, 0x6da42045, 0x600fef22, 0x41dace6b, 0x64f9bdd4,
        0x5d42d4fe, 0x76b1516d, 0x6fc9a717, 0x70ac4fb6, 0x00194ef6, 0x22b644e2, 0x1f7916d5,
        0x47581be2, 0x2710a123,
    ],
    [
        0x6284e867, 0x018d3afe, 0x5df99ef3, 0x4c1e467b, 0x566f6abc, 0x2994e427, 0x538a6d42,
        0x5d7bf2cf, 0x7fda2dab, 0x0fd854c4, 0x46922fca, 0x3d7763a1, 0x19fd05ca, 0x0a4bbb43,
        0x15075851, 0x3d903d76,
    ],
    [
        0x2d290ff7, 0x40809fa0, 0x59dac6ec, 0x127927a2, 0x6bbf0ea0, 0x0294140f, 0x24742976,
        0x6e84c081, 0x22484f4a, 0x354cae59, 0x0453ffe1, 0x3f47a3cc, 0x0088204e, 0x6066e109,
        0x3b7c4b80, 0x6b55665d,
    ],
    [
        0x3bc4b897, 0x735bf378, 0x508daf42, 0x1884fc2b, 0x7214f24c, 0x7498be0a, 0x1a60e640,
        0x3303f928, 0x29b46376, 0x5c96bb68, 0x65d097a5, 0x1d358e9f, 0x4a9a9017, 0x4724cf76,
        0x347af70f, 0x1e77e59a,
    ],
    [
        0x57090613, 0x1fa42108, 0x17bbef50, 0x1ff7e11c, 0x047b24ca, 0x4e140275, 0x4fa086f5,
        0x079b309c, 0x1159bd47, 0x6d37e4e5, 0x075d8dce, 0x12121ca0, 0x7f6a7c40, 0x68e182ba,
        0x5493201b, 0x0444a80e,
    ],
    [
        0x0064f4c6, 0x6467abe6, 0x66975762, 0x2af68f9b, 0x345b33be, 0x1b70d47f, 0x053db717,
        0x381189cb, 0x43b915f8, 0x20df3694, 0x0f459d26, 0x77a0e97b, 0x2f73e739, 0x1876c2f9,
        0x65a0e29a, 0x4cabefbe,
    ],
    [
        0x5abd1268, 0x4d34a760, 0x12771799, 0x69a0c9ac, 0x39091e55, 0x7f611cd0, 0x3af055da,
        0x7ac0bbdf, 0x6e0f3a24, 0x41e3b6f7, 0x49b3756d, 0x568bc538, 0x20c079d8, 0x1701c72c,
        0x7670dc6c, 0x5a439035,
    ],
    [
        0x7c93e00e, 0x561fbb4d, 0x1178907b, 0x02737406, 0x32fb24f1, 0x6323b60a, 0x6ab12418,
        0x42c99cea, 0x155a0b97, 0x53d1c6aa, 0x2bd20347, 0x279b3d73, 0x4f5f3c70, 0x0245af6c,
        0x238359d3, 0x49966a59,
    ],
];

/// Internal (partial-round) constants. Copied verbatim from
/// `mpz_circuits::circuits::poseidon2`.
const INT_RC_U32: [u32; N_PARTIAL_ROUNDS] = [
    0x7f7ec4bf, 0x0421926f, 0x5198e669, 0x34db3148, 0x4368bafd, 0x66685c7f, 0x78d3249a, 0x60187881,
    0x76dad67a, 0x0690b437, 0x1ea95311, 0x40e5369a, 0x38f103fc, 0x1d226a21,
];

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
        *s = *s * M31::from(MAT_INTERNAL_DIAG_M_1[i]) + sum;
    }
}

fn full_round_host(state: &mut [M31; N_STATE], rc: &[u32; N_STATE]) {
    for (s, c) in state.iter_mut().zip(rc.iter()) {
        *s += M31::from(*c);
    }
    for s in state.iter_mut() {
        *s = pow5_host(*s);
    }
    apply_external_matrix_host(state);
}

pub fn permute_host(state: &mut [M31; N_STATE]) {
    apply_external_matrix_host(state);
    for rc in EXT_RC_U32.iter().take(N_HALF_FULL_ROUNDS) {
        full_round_host(state, rc);
    }
    for rc in INT_RC_U32.iter() {
        state[0] += M31::from(*rc);
        state[0] = pow5_host(state[0]);
        apply_internal_matrix_host(state);
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
        let factor_var = ctx.constant(QM31::from(M31::from(MAT_INTERNAL_DIAG_M_1[i])));
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
    for s in state.iter_mut() {
        *s = pow5_in_circuit(ctx, *s);
    }
    apply_external_matrix_in_circuit(ctx, state);
}

/// One full Poseidon2-M31 permutation expressed as STARK constraints
/// over the supplied `state` vars.
pub fn permute_in_circuit<V: IValue>(ctx: &mut Context<V>, state: &mut [Var; N_STATE]) {
    apply_external_matrix_in_circuit(ctx, state);
    for rc in EXT_RC_U32.iter().take(N_HALF_FULL_ROUNDS) {
        full_round_in_circuit(ctx, state, rc);
    }
    for rc in INT_RC_U32.iter() {
        let rc_var = ctx.constant(QM31::from(M31::from(*rc)));
        state[0] = add(ctx, state[0], rc_var);
        state[0] = pow5_in_circuit(ctx, state[0]);
        apply_internal_matrix_in_circuit(ctx, state);
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
