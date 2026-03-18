use std::convert::AsPrimitive;

global ATTESTATION_LEN: u32 = 32;
global TX_ID_WIDTH: u32 = 10;
global USER_ID_WIDTH: u32 = 10;
global AMOUNT_WIDTH: u32 = 12;

fn main(
    attestation_committed_hash: pub [u8; 32],
    tx_id: pub u64,
    to_user_id: pub u64,
    amount: pub u64,
    attestation: str<ATTESTATION_LEN>,
    attestation_blinder: [u8; 16],
) {
    verify_commitment(
        attestation_committed_hash,
        attestation,
        attestation_blinder,
    );

    let parsed_tx_id = parse_decimal_bytes(tx_id_bytes(attestation));
    let parsed_to_user_id = parse_decimal_bytes(to_user_id_bytes(attestation));
    let parsed_amount = parse_decimal_bytes(amount_bytes(attestation));

    assert(parsed_tx_id == tx_id, "tx_id mismatch");
    assert(parsed_to_user_id == to_user_id, "to_user_id mismatch");
    assert(parsed_amount == amount, "amount mismatch");
}

fn verify_commitment<let N: u32>(
    committed_hash: [u8; 32],
    attestation: str<N>,
    blinder: [u8; 16],
) {
    let computed_hash = hash(build_hash_input(attestation, blinder));
    assert_eq(committed_hash, computed_hash, "Commitment hash mismatch");
}

fn parse_decimal_bytes<let N: u32>(input: [u8; N]) -> u64 {
    let mut result = 0;

    for i in 0..N {
        let digit = input[i].as_() - 48;
        assert(digit >= 0, "digit underflow");
        assert(digit <= 9, "digit overflow");

        let digit_u64: u64 = digit.as_();
        result *= 10;
        result += digit_u64;
    }

    result
}

fn tx_id_bytes(input: str<ATTESTATION_LEN>) -> [u8; TX_ID_WIDTH] {
    let input_bytes = input.as_bytes();
    let mut output: [u8; TX_ID_WIDTH] = [0; TX_ID_WIDTH];

    for i in 0..TX_ID_WIDTH {
        output[i] = input_bytes[i];
    }

    output
}

fn to_user_id_bytes(input: str<ATTESTATION_LEN>) -> [u8; USER_ID_WIDTH] {
    let input_bytes = input.as_bytes();
    let mut output: [u8; USER_ID_WIDTH] = [0; USER_ID_WIDTH];

    for i in 0..USER_ID_WIDTH {
        output[i] = input_bytes[TX_ID_WIDTH + i];
    }

    output
}

fn amount_bytes(input: str<ATTESTATION_LEN>) -> [u8; AMOUNT_WIDTH] {
    let input_bytes = input.as_bytes();
    let mut output: [u8; AMOUNT_WIDTH] = [0; AMOUNT_WIDTH];

    for i in 0..AMOUNT_WIDTH {
        output[i] = input_bytes[TX_ID_WIDTH + USER_ID_WIDTH + i];
    }

    output
}

fn hash<let N: u32>(input: [u8; N]) -> [u8; 32] {
    std::hash::blake3(input)
}

fn build_hash_input<let N: u32>(attestation: str<N>, blinder: [u8; 16]) -> [u8; 16 + N] {
    let mut input: [u8; 16 + N] = [0; 16 + N];
    let attestation_bytes = attestation.as_bytes();

    for i in 0..N {
        input[i] = attestation_bytes[i];
    }
    for i in 0..16 {
        input[N + i] = blinder[i];
    }

    input
}

#[test]
fn test_parse_decimal_bytes() {
    assert_eq(parse_decimal_bytes("0000000001".as_bytes()), 1);
    assert_eq(parse_decimal_bytes("0000000025".as_bytes()), 25);
    assert_eq(parse_decimal_bytes("000000000123".as_bytes()), 123);
}

#[test]
fn test_main_with_attestation() {
    let attestation = "00000000010000000003000000000025";
    let attestation_blinder = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let input = build_hash_input(attestation, attestation_blinder);
    let attestation_committed_hash = hash(input);

    main(
        attestation_committed_hash,
        1,
        3,
        25,
        attestation,
        attestation_blinder,
    );
}
