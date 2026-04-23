use std::verify_proof_with_type;

global HONK_VK_SIZE: u32 = 115;
// bb 5.0 RECURSIVE_ZK_PROOF_LENGTH for PROOF_TYPE_HONK_ZK=6
global HONK_PROOF_SIZE: u32 = 458;
global HONK_IDENTIFIER: u32 = 6;
global INNER_PUBLIC_INPUTS: u32 = 35;
global PREV_PUBLIC_INPUTS: u32 = 7;

fn field_to_u64(value: Field) -> u64 {
    let narrowed = value as u64;
    assert(narrowed as Field == value, "value exceeds u64");
    narrowed
}

fn checked_total(prev_total: Field, amount: Field) -> Field {
    let _prev_total = field_to_u64(prev_total);
    let _amount = field_to_u64(amount);
    let total_amount = prev_total + amount;
    let _total_amount = field_to_u64(total_amount);
    total_amount
}

fn next_transfers_root(prev_root: Field, tx_id: Field, amount: Field) -> Field {
    let leaf = std::hash::pedersen_hash([tx_id, amount]);
    std::hash::pedersen_hash([prev_root, leaf])
}

fn main(
    inner_vk: [Field; HONK_VK_SIZE],
    inner_proof: [Field; HONK_PROOF_SIZE],
    inner_public_inputs: [Field; INNER_PUBLIC_INPUTS],
    inner_key_hash: Field,
    prev_vk: [Field; HONK_VK_SIZE],
    prev_proof: [Field; HONK_PROOF_SIZE],
    prev_public_inputs: [Field; PREV_PUBLIC_INPUTS],
    prev_key_hash: Field,
    allowed_null_vk_hash: Field,
    allowed_recursive_vk_hash: Field,
    allowed_inner_vk_hash: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field) {
    assert(inner_key_hash == allowed_inner_vk_hash, "inner VK not canonical");

    let is_null = prev_key_hash == allowed_null_vk_hash;
    let is_recursive = prev_key_hash == allowed_recursive_vk_hash;
    assert(is_null | is_recursive, "prev VK not in allowed set");

    verify_proof_with_type(
        inner_vk,
        inner_proof,
        inner_public_inputs,
        inner_key_hash,
        HONK_IDENTIFIER,
    );
    verify_proof_with_type(
        prev_vk,
        prev_proof,
        prev_public_inputs,
        prev_key_hash,
        HONK_IDENTIFIER,
    );

    let inner_tx_id = inner_public_inputs[32];
    let inner_to_user_id = inner_public_inputs[33];
    let inner_amount = inner_public_inputs[34];

    let prev_total = prev_public_inputs[1];
    let prev_root = prev_public_inputs[2];
    let prev_to_user_id = prev_public_inputs[3];
    let prev_null_hash = prev_public_inputs[4];
    let prev_recursive_hash = prev_public_inputs[5];
    let prev_inner_hash = prev_public_inputs[6];

    assert(prev_null_hash == allowed_null_vk_hash, "null VK hash chain broken");
    assert(prev_recursive_hash == allowed_recursive_vk_hash, "recursive VK hash chain broken");
    assert(prev_inner_hash == allowed_inner_vk_hash, "inner VK hash chain broken");

    assert(prev_to_user_id == inner_to_user_id, "prev to_user_id mismatch");

    let total_amount = checked_total(prev_total, inner_amount);
    let transfers_root = next_transfers_root(prev_root, inner_tx_id, inner_amount);

    (
        0, total_amount, transfers_root, inner_to_user_id, allowed_null_vk_hash,
        allowed_recursive_vk_hash, allowed_inner_vk_hash,
    )
}

#[test]
fn test_checked_total_accumulates_u64_values() {
    assert(checked_total(25, 10) == 35);
}

#[test(should_fail)]
fn test_checked_total_rejects_u64_overflow() {
    let _overflow = checked_total(18446744073709551615, 1);
}

#[test]
fn test_next_transfers_root_matches_pedersen_chain() {
    let expected_leaf = std::hash::pedersen_hash([1, 25]);
    let expected_root = std::hash::pedersen_hash([0, expected_leaf]);
    assert(next_transfers_root(0, 1, 25) == expected_root);
}
