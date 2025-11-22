use std::convert::AsPrimitive;

fn main(committed_hash: pub [u8; 32], balance: str<3>, blinder: [u8; 16]) {
    verify_commitment(committed_hash, balance, blinder);
    verify_balance_range(balance);
}

fn verify_commitment(committed_hash: [u8; 32], balance: str<3>, blinder: [u8; 16]) {
    let prefix = "\"balance\":";
    let prefixed_balance = concatenate(prefix, balance);
    let suffix = "}";
    let balance = concatenate(prefixed_balance, suffix);
    let input = build_hash_input(balance, blinder);
    let computed_hash = hash(input);
    assert_eq(committed_hash, computed_hash);
}

fn verify_balance_range(balance: str<3>) {
    let balance_num = str_to_num(balance);
    assert(balance_num.as_() > 10);
    assert(balance_num.as_() < 200);
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

fn concatenate<let N: u32, let M: u32>(x: str<N>, y: str<M>) -> str<N + M> {
    let mut result: [u8; N + M] = [0; N + M];
    let x_bytes = x.as_bytes();
    let y_bytes = y.as_bytes();

    for i in 0..N {
        result[i] = x_bytes[i];
    }
    for i in 0..M {
        result[N + i] = y_bytes[i];
    }

    result.as_str_unchecked()
}

fn hash<let N: u32>(input: [u8; N]) -> [u8; 32] {
    std::hash::blake3(input)
}

fn build_hash_input<let N: u32>(x: str<N>, blinder: [u8; 16]) -> [u8; 16 + N] {
    let mut input: [u8; 16 + N] = [0; 16 + N];
    let x_bytes = x.as_bytes();

    for i in 0..N {
        input[i] = x_bytes[i];
    }
    for i in 0..16 {
        input[N + i] = blinder[i];
    }
    input
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
    let expected = [
        179, 212, 248, 128, 63, 126, 36, 184, 243, 137, 176, 114, 231, 84, 119, 205, 188, 251, 224,
        116, 8, 15, 181, 229, 0, 229, 62, 38, 224, 84, 21, 142,
    ];
    assert_eq(hash("123".as_bytes()), expected);
}

#[test]
fn test_main() {
    let committed_hash = [
        233, 174, 98, 17, 91, 53, 186, 186, 149, 166, 195, 212, 75, 101, 1, 185, 36, 223, 39, 228,
        100, 246, 161, 151, 53, 21, 86, 81, 166, 92, 209, 96,
    ];
    let balance = "100";
    let blinder = [220, 160, 73, 26, 55, 51, 173, 103, 71, 107, 236, 59, 85, 220, 38, 142];
    main(committed_hash, balance, blinder);
}
