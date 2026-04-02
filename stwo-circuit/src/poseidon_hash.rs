use std::ops::{Add, AddAssign, Mul, Sub};

use stwo::core::fields::{FieldExpOps, m31::BaseField};

pub const N_STATE: usize = 16;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const LOG_EXPAND: u32 = 3;

// Real Poseidon2 round constants for M31 field (from zkhash)
// Source: https://github.com/AntoineFONDEUR/poseidon2/blob/poseidon2-M31/plain_implementations/src/poseidon2/poseidon2_instance_m31.rs
pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; 2 * N_HALF_FULL_ROUNDS] = [
    // First 4 full rounds (RC16[0..4])
    [
        BaseField::from_u32_unchecked(0x768bab52),
        BaseField::from_u32_unchecked(0x70e0ab7d),
        BaseField::from_u32_unchecked(0x3d266c8a),
        BaseField::from_u32_unchecked(0x6da42045),
        BaseField::from_u32_unchecked(0x600fef22),
        BaseField::from_u32_unchecked(0x41dace6b),
        BaseField::from_u32_unchecked(0x64f9bdd4),
        BaseField::from_u32_unchecked(0x5d42d4fe),
        BaseField::from_u32_unchecked(0x76b1516d),
        BaseField::from_u32_unchecked(0x6fc9a717),
        BaseField::from_u32_unchecked(0x70ac4fb6),
        BaseField::from_u32_unchecked(0x00194ef6),
        BaseField::from_u32_unchecked(0x22b644e2),
        BaseField::from_u32_unchecked(0x1f7916d5),
        BaseField::from_u32_unchecked(0x47581be2),
        BaseField::from_u32_unchecked(0x2710a123),
    ],
    [
        BaseField::from_u32_unchecked(0x6284e867),
        BaseField::from_u32_unchecked(0x018d3afe),
        BaseField::from_u32_unchecked(0x5df99ef3),
        BaseField::from_u32_unchecked(0x4c1e467b),
        BaseField::from_u32_unchecked(0x566f6abc),
        BaseField::from_u32_unchecked(0x2994e427),
        BaseField::from_u32_unchecked(0x538a6d42),
        BaseField::from_u32_unchecked(0x5d7bf2cf),
        BaseField::from_u32_unchecked(0x7fda2dab),
        BaseField::from_u32_unchecked(0x0fd854c4),
        BaseField::from_u32_unchecked(0x46922fca),
        BaseField::from_u32_unchecked(0x3d7763a1),
        BaseField::from_u32_unchecked(0x19fd05ca),
        BaseField::from_u32_unchecked(0x0a4bbb43),
        BaseField::from_u32_unchecked(0x15075851),
        BaseField::from_u32_unchecked(0x3d903d76),
    ],
    [
        BaseField::from_u32_unchecked(0x2d290ff7),
        BaseField::from_u32_unchecked(0x40809fa0),
        BaseField::from_u32_unchecked(0x59dac6ec),
        BaseField::from_u32_unchecked(0x127927a2),
        BaseField::from_u32_unchecked(0x6bbf0ea0),
        BaseField::from_u32_unchecked(0x0294140f),
        BaseField::from_u32_unchecked(0x24742976),
        BaseField::from_u32_unchecked(0x6e84c081),
        BaseField::from_u32_unchecked(0x22484f4a),
        BaseField::from_u32_unchecked(0x354cae59),
        BaseField::from_u32_unchecked(0x0453ffe1),
        BaseField::from_u32_unchecked(0x3f47a3cc),
        BaseField::from_u32_unchecked(0x0088204e),
        BaseField::from_u32_unchecked(0x6066e109),
        BaseField::from_u32_unchecked(0x3b7c4b80),
        BaseField::from_u32_unchecked(0x6b55665d),
    ],
    [
        BaseField::from_u32_unchecked(0x3bc4b897),
        BaseField::from_u32_unchecked(0x735bf378),
        BaseField::from_u32_unchecked(0x508daf42),
        BaseField::from_u32_unchecked(0x1884fc2b),
        BaseField::from_u32_unchecked(0x7214f24c),
        BaseField::from_u32_unchecked(0x7498be0a),
        BaseField::from_u32_unchecked(0x1a60e640),
        BaseField::from_u32_unchecked(0x3303f928),
        BaseField::from_u32_unchecked(0x29b46376),
        BaseField::from_u32_unchecked(0x5c96bb68),
        BaseField::from_u32_unchecked(0x65d097a5),
        BaseField::from_u32_unchecked(0x1d358e9f),
        BaseField::from_u32_unchecked(0x4a9a9017),
        BaseField::from_u32_unchecked(0x4724cf76),
        BaseField::from_u32_unchecked(0x347af70f),
        BaseField::from_u32_unchecked(0x1e77e59a),
    ],
    // Last 4 full rounds (RC16[18..22])
    [
        BaseField::from_u32_unchecked(0x57090613),
        BaseField::from_u32_unchecked(0x1fa42108),
        BaseField::from_u32_unchecked(0x17bbef50),
        BaseField::from_u32_unchecked(0x1ff7e11c),
        BaseField::from_u32_unchecked(0x047b24ca),
        BaseField::from_u32_unchecked(0x4e140275),
        BaseField::from_u32_unchecked(0x4fa086f5),
        BaseField::from_u32_unchecked(0x079b309c),
        BaseField::from_u32_unchecked(0x1159bd47),
        BaseField::from_u32_unchecked(0x6d37e4e5),
        BaseField::from_u32_unchecked(0x075d8dce),
        BaseField::from_u32_unchecked(0x12121ca0),
        BaseField::from_u32_unchecked(0x7f6a7c40),
        BaseField::from_u32_unchecked(0x68e182ba),
        BaseField::from_u32_unchecked(0x5493201b),
        BaseField::from_u32_unchecked(0x0444a80e),
    ],
    [
        BaseField::from_u32_unchecked(0x0064f4c6),
        BaseField::from_u32_unchecked(0x6467abe6),
        BaseField::from_u32_unchecked(0x66975762),
        BaseField::from_u32_unchecked(0x2af68f9b),
        BaseField::from_u32_unchecked(0x345b33be),
        BaseField::from_u32_unchecked(0x1b70d47f),
        BaseField::from_u32_unchecked(0x053db717),
        BaseField::from_u32_unchecked(0x381189cb),
        BaseField::from_u32_unchecked(0x43b915f8),
        BaseField::from_u32_unchecked(0x20df3694),
        BaseField::from_u32_unchecked(0x0f459d26),
        BaseField::from_u32_unchecked(0x77a0e97b),
        BaseField::from_u32_unchecked(0x2f73e739),
        BaseField::from_u32_unchecked(0x1876c2f9),
        BaseField::from_u32_unchecked(0x65a0e29a),
        BaseField::from_u32_unchecked(0x4cabefbe),
    ],
    [
        BaseField::from_u32_unchecked(0x5abd1268),
        BaseField::from_u32_unchecked(0x4d34a760),
        BaseField::from_u32_unchecked(0x12771799),
        BaseField::from_u32_unchecked(0x69a0c9ac),
        BaseField::from_u32_unchecked(0x39091e55),
        BaseField::from_u32_unchecked(0x7f611cd0),
        BaseField::from_u32_unchecked(0x3af055da),
        BaseField::from_u32_unchecked(0x7ac0bbdf),
        BaseField::from_u32_unchecked(0x6e0f3a24),
        BaseField::from_u32_unchecked(0x41e3b6f7),
        BaseField::from_u32_unchecked(0x49b3756d),
        BaseField::from_u32_unchecked(0x568bc538),
        BaseField::from_u32_unchecked(0x20c079d8),
        BaseField::from_u32_unchecked(0x1701c72c),
        BaseField::from_u32_unchecked(0x7670dc6c),
        BaseField::from_u32_unchecked(0x5a439035),
    ],
    [
        BaseField::from_u32_unchecked(0x7c93e00e),
        BaseField::from_u32_unchecked(0x561fbb4d),
        BaseField::from_u32_unchecked(0x1178907b),
        BaseField::from_u32_unchecked(0x02737406),
        BaseField::from_u32_unchecked(0x32fb24f1),
        BaseField::from_u32_unchecked(0x6323b60a),
        BaseField::from_u32_unchecked(0x6ab12418),
        BaseField::from_u32_unchecked(0x42c99cea),
        BaseField::from_u32_unchecked(0x155a0b97),
        BaseField::from_u32_unchecked(0x53d1c6aa),
        BaseField::from_u32_unchecked(0x2bd20347),
        BaseField::from_u32_unchecked(0x279b3d73),
        BaseField::from_u32_unchecked(0x4f5f3c70),
        BaseField::from_u32_unchecked(0x0245af6c),
        BaseField::from_u32_unchecked(0x238359d3),
        BaseField::from_u32_unchecked(0x49966a59),
    ],
];

pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] = [
    BaseField::from_u32_unchecked(0x7f7ec4bf),
    BaseField::from_u32_unchecked(0x0421926f),
    BaseField::from_u32_unchecked(0x5198e669),
    BaseField::from_u32_unchecked(0x34db3148),
    BaseField::from_u32_unchecked(0x4368bafd),
    BaseField::from_u32_unchecked(0x66685c7f),
    BaseField::from_u32_unchecked(0x78d3249a),
    BaseField::from_u32_unchecked(0x60187881),
    BaseField::from_u32_unchecked(0x76dad67a),
    BaseField::from_u32_unchecked(0x0690b437),
    BaseField::from_u32_unchecked(0x1ea95311),
    BaseField::from_u32_unchecked(0x40e5369a),
    BaseField::from_u32_unchecked(0x38f103fc),
    BaseField::from_u32_unchecked(0x1d226a21),
];

pub const MAT_INTERNAL_DIAG_M_1: [BaseField; N_STATE] = [
    BaseField::from_u32_unchecked(0x07b80ac4),
    BaseField::from_u32_unchecked(0x6bd9cb33),
    BaseField::from_u32_unchecked(0x48ee3f9f),
    BaseField::from_u32_unchecked(0x4f63dd19),
    BaseField::from_u32_unchecked(0x18c546b3),
    BaseField::from_u32_unchecked(0x5af89e8b),
    BaseField::from_u32_unchecked(0x4ff23de8),
    BaseField::from_u32_unchecked(0x4f78aaf6),
    BaseField::from_u32_unchecked(0x53bdc6d4),
    BaseField::from_u32_unchecked(0x5c59823e),
    BaseField::from_u32_unchecked(0x2a471c72),
    BaseField::from_u32_unchecked(0x4c975e79),
    BaseField::from_u32_unchecked(0x58dc64d4),
    BaseField::from_u32_unchecked(0x06e9315d),
    BaseField::from_u32_unchecked(0x2cf32286),
    BaseField::from_u32_unchecked(0x2fb6755d),
];

#[inline(always)]
pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

pub fn apply_external_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

pub fn apply_internal_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // Compute sum of all elements
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);

    // Apply: state[i] = state[i] * MAT_INTERNAL_DIAG_M_1[i] + sum
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * MAT_INTERNAL_DIAG_M_1[i] + sum.clone();
    });
}

pub fn pow5<F: FieldExpOps>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}

pub fn pow5_expr<F: Clone + std::ops::Mul<Output = F>>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x
}
