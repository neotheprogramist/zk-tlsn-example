use std::convert::AsPrimitive;

// Constant for the committed part length
global COMMITTED_PART_LEN: u32 = 12; // Balance value up to 12 chars (e.g., "100" with padding)

fn main(
    balance_committed_hash: pub [u8; 32], // Public: hash of committed part
    balance_committed_part: str<COMMITTED_PART_LEN>, // Private: actual balance value
    balance_blinder: [u8; 16], // Private: blinder for commitment
) {
    // Verify the commitment to the balance part
    verify_commitment(
        balance_committed_hash,
        balance_committed_part,
        balance_blinder,
    );

    // Extract and verify the numeric balance from the committed part
    let _balance = str_to_num_with_padding(balance_committed_part);
}

fn verify_commitment<let N: u32>(
    committed_hash: [u8; 32],
    balance_committed_part: str<N>,
    blinder: [u8; 16],
) {
    // Hash the committed part (balance value) with the blinder
    let computed_hash = hash(build_hash_input(balance_committed_part, blinder));
    assert_eq(committed_hash, computed_hash, "Commitment hash mismatch");
}

fn str_to_num_with_padding<let N: u32>(input: str<N>) -> i64 {
    let input_bytes = input.as_bytes();
    let mut result = 0;
    let mut is_broken = false;
    for i in 0..N {
        let val = input_bytes[i].as_() - 48;
        if !((val >= 0) & (val <= 9)) {
            is_broken = true;
        }
        if !is_broken {
            result *= 10;
            result += val;
        }
    }
    result
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
fn test_hash() {
    let expected = [
        179, 212, 248, 128, 63, 126, 36, 184, 243, 137, 176, 114, 231, 84, 119, 205, 188, 251, 224,
        116, 8, 15, 181, 229, 0, 229, 62, 38, 224, 84, 21, 142,
    ];
    assert_eq(hash("123".as_bytes()), expected);
}

#[test]
fn test_str_to_num_with_padding() {
    assert_eq(str_to_num_with_padding("},32817489"), 0);
    assert_eq(str_to_num_with_padding("100}        "), 100);
    assert_eq(str_to_num_with_padding("99,123    43"), 99);
    assert_eq(str_to_num_with_padding("1234}     88"), 1234);
}

#[test]
fn test_main_with_committed_part() {
    // The committed part is just the balance value: "100}" padded to 12 chars
    let balance_committed_part = "100}        "; // 12 chars: "100}" + 8 spaces
    let balance_blinder = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // Compute expected hash of the committed part
    let input = build_hash_input(balance_committed_part, balance_blinder);
    let balance_committed_hash = hash(input);

    // Run main - verifier already knows "balance": was revealed
    main(
        balance_committed_hash,
        balance_committed_part,
        balance_blinder,
    );
}
