use circuits::context::{Context, Var};
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::eval;

const N_STATE: usize = 16;
const N_PARTIAL_ROUNDS: usize = 14;
const N_HALF_FULL_ROUNDS: usize = 4;

const RC_EXTERNAL: [[u32; N_STATE]; 8] = [
    [0x768bab52, 0x70e0ab7d, 0x3d266c8a, 0x6da42045, 0x600fef22, 0x41dace6b, 0x64f9bdd4, 0x5d42d4fe, 0x76b1516d, 0x6fc9a717, 0x70ac4fb6, 0x00194ef6, 0x22b644e2, 0x1f7916d5, 0x47581be2, 0x2710a123],
    [0x6284e867, 0x018d3afe, 0x5df99ef3, 0x4c1e467b, 0x566f6abc, 0x2994e427, 0x538a6d42, 0x5d7bf2cf, 0x7fda2dab, 0x0fd854c4, 0x46922fca, 0x3d7763a1, 0x19fd05ca, 0x0a4bbb43, 0x15075851, 0x3d903d76],
    [0x2d290ff7, 0x40809fa0, 0x59dac6ec, 0x127927a2, 0x6bbf0ea0, 0x0294140f, 0x24742976, 0x6e84c081, 0x22484f4a, 0x354cae59, 0x0453ffe1, 0x3f47a3cc, 0x0088204e, 0x6066e109, 0x3b7c4b80, 0x6b55665d],
    [0x3bc4b897, 0x735bf378, 0x508daf42, 0x1884fc2b, 0x7214f24c, 0x7498be0a, 0x1a60e640, 0x3303f928, 0x29b46376, 0x5c96bb68, 0x65d097a5, 0x1d358e9f, 0x4a9a9017, 0x4724cf76, 0x347af70f, 0x1e77e59a],
    [0x57090613, 0x1fa42108, 0x17bbef50, 0x1ff7e11c, 0x047b24ca, 0x4e140275, 0x4fa086f5, 0x079b309c, 0x1159bd47, 0x6d37e4e5, 0x075d8dce, 0x12121ca0, 0x7f6a7c40, 0x68e182ba, 0x5493201b, 0x0444a80e],
    [0x0064f4c6, 0x6467abe6, 0x66975762, 0x2af68f9b, 0x345b33be, 0x1b70d47f, 0x053db717, 0x381189cb, 0x43b915f8, 0x20df3694, 0x0f459d26, 0x77a0e97b, 0x2f73e739, 0x1876c2f9, 0x65a0e29a, 0x4cabefbe],
    [0x5abd1268, 0x4d34a760, 0x12771799, 0x69a0c9ac, 0x39091e55, 0x7f611cd0, 0x3af055da, 0x7ac0bbdf, 0x6e0f3a24, 0x41e3b6f7, 0x49b3756d, 0x568bc538, 0x20c079d8, 0x1701c72c, 0x7670dc6c, 0x5a439035],
    [0x7c93e00e, 0x561fbb4d, 0x1178907b, 0x02737406, 0x32fb24f1, 0x6323b60a, 0x6ab12418, 0x42c99cea, 0x155a0b97, 0x53d1c6aa, 0x2bd20347, 0x279b3d73, 0x4f5f3c70, 0x0245af6c, 0x238359d3, 0x49966a59],
];
const RC_INTERNAL: [u32; N_PARTIAL_ROUNDS] = [
    0x7f7ec4bf, 0x0421926f, 0x5198e669, 0x34db3148, 0x4368bafd, 0x66685c7f, 0x78d3249a,
    0x60187881, 0x76dad67a, 0x0690b437, 0x1ea95311, 0x40e5369a, 0x38f103fc, 0x1d226a21,
];
const INTERNAL_DIAG: [u32; N_STATE] = [
    0x07b80ac4, 0x6bd9cb33, 0x48ee3f9f, 0x4f63dd19, 0x18c546b3, 0x5af89e8b, 0x4ff23de8,
    0x4f78aaf6, 0x53bdc6d4, 0x5c59823e, 0x2a471c72, 0x4c975e79, 0x58dc64d4, 0x06e9315d,
    0x2cf32286, 0x2fb6755d,
];

fn add<Value: IValue>(ctx: &mut Context<Value>, a: Var, b: Var) -> Var {
    eval!(ctx, (a) + (b))
}

fn add3<Value: IValue>(ctx: &mut Context<Value>, a: Var, b: Var, c: Var) -> Var {
    let t = add(ctx, a, b);
    add(ctx, t, c)
}

fn add4<Value: IValue>(ctx: &mut Context<Value>, a: Var, b: Var, c: Var, d: Var) -> Var {
    let t = add3(ctx, a, b, c);
    add(ctx, t, d)
}

fn pow5<Value: IValue>(ctx: &mut Context<Value>, x: Var) -> Var {
    let x2 = eval!(ctx, (x) * (x));
    let x4 = eval!(ctx, (x2) * (x2));
    eval!(ctx, (x4) * (x))
}

fn apply_m4<Value: IValue>(ctx: &mut Context<Value>, x0: Var, x1: Var, x2: Var, x3: Var) -> [Var; 4] {
    let t0 = add(ctx, x0, x1);
    let t02 = add(ctx, t0, t0);
    let t1 = add(ctx, x2, x3);
    let t12 = add(ctx, t1, t1);
    let t2 = add3(ctx, x1, x1, t1);
    let t3 = add3(ctx, x3, x3, t0);
    let t4 = add3(ctx, t12, t12, t3);
    let t5 = add3(ctx, t02, t02, t2);
    let t6 = add(ctx, t3, t5);
    let t7 = add(ctx, t2, t4);
    [t6, t5, t7, t4]
}

fn apply_external_round_matrix<Value: IValue>(ctx: &mut Context<Value>, state: &mut [Var; 16]) {
    for i in 0..4 {
        let base = 4 * i;
        let [a, b, c, d] = apply_m4(ctx, state[base], state[base + 1], state[base + 2], state[base + 3]);
        state[base] = a;
        state[base + 1] = b;
        state[base + 2] = c;
        state[base + 3] = d;
    }
    for j in 0..4 {
        let s = add4(ctx, state[j], state[j + 4], state[j + 8], state[j + 12]);
        for i in 0..4 {
            let idx = 4 * i + j;
            state[idx] = add(ctx, state[idx], s);
        }
    }
}

fn apply_internal_round_matrix<Value: IValue>(ctx: &mut Context<Value>, state: &mut [Var; 16]) {
    let mut sum = state[0];
    for i in 1..N_STATE {
        sum = add(ctx, sum, state[i]);
    }
    for i in 0..N_STATE {
        let coeff = ctx.constant(qm31_from_u32s(INTERNAL_DIAG[i], 0, 0, 0));
        let prod = eval!(ctx, (state[i]) * (coeff));
        state[i] = add(ctx, prod, sum);
    }
}

/// Poseidon2 hash for two field elements (state[0]=a, state[1]=b).
/// Matches `Poseidon2.sol` parameters for M31.
pub fn poseidon2_hash_two<Value: IValue>(ctx: &mut Context<Value>, a: Var, b: Var) -> Var {
    let zero = ctx.zero();
    let mut state = [zero; 16];
    state[0] = a;
    state[1] = b;

    // Initial external round matrix.
    apply_external_round_matrix(ctx, &mut state);

    // First half full rounds.
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            let rc = ctx.constant(qm31_from_u32s(RC_EXTERNAL[round][i], 0, 0, 0));
            state[i] = add(ctx, state[i], rc);
        }
        for i in 0..N_STATE {
            state[i] = pow5(ctx, state[i]);
        }
        apply_external_round_matrix(ctx, &mut state);
    }

    // Partial rounds.
    for r in 0..N_PARTIAL_ROUNDS {
        let rc = ctx.constant(qm31_from_u32s(RC_INTERNAL[r], 0, 0, 0));
        state[0] = add(ctx, state[0], rc);
        state[0] = pow5(ctx, state[0]);
        apply_internal_round_matrix(ctx, &mut state);
    }

    // Second half full rounds.
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            let rc = ctx.constant(qm31_from_u32s(RC_EXTERNAL[round + N_HALF_FULL_ROUNDS][i], 0, 0, 0));
            state[i] = add(ctx, state[i], rc);
        }
        for i in 0..N_STATE {
            state[i] = pow5(ctx, state[i]);
        }
        apply_external_round_matrix(ctx, &mut state);
    }

    for lane in &state[1..] {
        ctx.mark_as_maybe_unused(lane);
    }

    state[0]
}

