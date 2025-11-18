use std::convert::AsPrimitive;

fn main(
    // Public inputs
    committed_hash: pub [u8; 32],
    // Private inputs
    amount: str<3>,
    blinder: [u8; 16],
) {
    assert_eq(committed_hash, hash(amount, blinder));
    let amount = str_to_num(amount);
    assert(amount.as_() > 10);
    assert(amount.as_() < 200);
}

fn str_to_num<let N: u32>(x: str<N>) -> Field {
    let x_bytes = x.as_bytes();
    let mut result = 0;
    for i in 0..N {
        result *= 10;
        result += x_bytes[i].as_() - 48;
    }
    result
}

fn hash<let N: u32>(x: str<N>, blinder: [u8; 16]) -> [u8; 32] {
    let mut input: [u8; 16 + N] = [0; 16 + N];
    for i in 0..N {
        input[i] = x.as_bytes()[i];
    }
    for i in 0..16 {
        input[N + i] = blinder[i];
    }
    sha256::sha256_var(input, 16 + N.as_())
}

#[test]
fn test_str_to_num() {
    assert_eq(str_to_num(""), 0);
    assert_eq(str_to_num("0"), 0);
    assert_eq(str_to_num("1"), 1);
    assert_eq(str_to_num("11"), 11);
    assert_eq(str_to_num("123"), 123);
    assert_eq(str_to_num("1234"), 1234);
}

#[test]
fn test_hash() {
    println(hash("123", [0; 16]));
    assert_eq(
        hash("123", [0; 16]),
        [
            119, 146, 69, 56, 13, 105, 118, 109, 226, 15, 41, 180, 79, 176, 197, 231, 55, 139, 223,
            17, 241, 93, 110, 72, 171, 203, 7, 30, 69, 142, 228, 135,
        ],
    );
}

#[test]
fn test_main() {
    let committed_hash = [
        119, 146, 69, 56, 13, 105, 118, 109, 226, 15, 41, 180, 79, 176, 197, 231, 55, 139, 223, 17,
        241, 93, 110, 72, 171, 203, 7, 30, 69, 142, 228, 135,
    ];
    let amount = "123";
    let blinder = [0; 16];
    main(committed_hash, amount, blinder);
}
