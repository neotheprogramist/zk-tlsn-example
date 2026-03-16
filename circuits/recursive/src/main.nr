mod generated_constants;

global HONK_IDENTIFIER: u32 = 1;
global INNER_PUBLIC_INPUTS: u32 = 35;
global PREV_PUBLIC_INPUTS: u32 = 6;

fn field_to_u64(value: Field) -> u64 {
    let narrowed = value as u64;
    assert(narrowed as Field == value);
    narrowed
}

fn main(
    inner_vk: [Field; generated_constants::HONK_VK_FIELDS],
    inner_proof: [Field; generated_constants::HONK_PROOF_FIELDS],
    inner_public_inputs: [Field; INNER_PUBLIC_INPUTS],
    inner_key_hash: Field,
    prev_vk: [Field; generated_constants::HONK_VK_FIELDS],
    prev_proof: [Field; generated_constants::HONK_PROOF_FIELDS],
    prev_public_inputs: [Field; PREV_PUBLIC_INPUTS],
    prev_key_hash: Field,
    allowed_null_vk_hash: Field,
    allowed_recursive_vk_hash: Field,
) -> pub (Field, Field, Field, Field, Field, Field) {
    assert(
        inner_key_hash == generated_constants::EXPECTED_INNER_VK_HASH,
        "inner VK not canonical",
    );

    let is_allowed_prev =
        if prev_key_hash == allowed_null_vk_hash { true } else { prev_key_hash == allowed_recursive_vk_hash };
    assert(is_allowed_prev, "prev VK not in allowed set");

    std::verify_proof_with_type(
        inner_vk,
        inner_proof,
        inner_public_inputs,
        inner_key_hash,
        HONK_IDENTIFIER,
    );
    std::verify_proof_with_type(
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

    assert(prev_null_hash == allowed_null_vk_hash, "null VK hash chain broken");
    assert(
        prev_recursive_hash == allowed_recursive_vk_hash,
        "recursive VK hash chain broken",
    );
    assert(prev_to_user_id == inner_to_user_id, "to_user_id mismatch");

    field_to_u64(inner_amount);
    field_to_u64(prev_total);
    let total_amount = prev_total + inner_amount;
    field_to_u64(total_amount);

    let leaf = std::hash::pedersen_hash([inner_tx_id, inner_amount]);
    let transfers_root = std::hash::pedersen_hash([prev_root, leaf]);

    (
        0,
        total_amount,
        transfers_root,
        inner_to_user_id,
        allowed_null_vk_hash,
        allowed_recursive_vk_hash,
    )
}
