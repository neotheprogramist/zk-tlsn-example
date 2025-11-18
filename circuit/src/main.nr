use std::convert::AsPrimitive;

fn main(committed_hash: pub [u8; 32], balance: str<3>, blinder: [u8; 16]) {
    verify_commitment(committed_hash, balance, blinder);
    verify_balance_range(balance);
}

fn verify_commitment(committed_hash: [u8; 32], balance: str<3>, blinder: [u8; 16]) {
    let prefix = "\"balance\":";
    let prefixed_balance = concatenate(prefix, balance);
    let computed_hash = hash(prefixed_balance, blinder);
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

fn hash<let N: u32>(x: str<N>, blinder: [u8; 16]) -> [u8; 32] {
    let input = build_hash_input(x, blinder);
    sha256::sha256_var(input, 16 + N.as_())
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
        191, 223, 50, 85, 120, 105, 23, 168, 180, 164, 48, 229, 45, 70, 22, 27, 204, 142, 45, 209,
        155, 239, 95, 4, 155, 237, 230, 185, 173, 146, 130, 144,
    ];
    let balance = "100";
    let blinder = [157, 25, 213, 0, 235, 93, 93, 108, 150, 227, 233, 45, 29, 95, 2, 180];
    main(committed_hash, balance, blinder);
}
