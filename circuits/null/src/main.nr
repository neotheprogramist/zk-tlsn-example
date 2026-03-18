fn main(
    to_user_id: Field,
    allowed_null_vk_hash: Field,
    allowed_recursive_vk_hash: Field,
    allowed_inner_vk_hash: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field) {
    (
        0,
        0,
        0,
        to_user_id,
        allowed_null_vk_hash,
        allowed_recursive_vk_hash,
        allowed_inner_vk_hash,
    )
}

#[test]
fn test_main_outputs_zero_bootstrap_state() {
    let (reserved, total_amount, transfers_root, actual_to_user_id, null_vk_hash, recursive_vk_hash, inner_vk_hash) =
        main(3, 42, 77, 99);

    assert(reserved == 0);
    assert(total_amount == 0);
    assert(transfers_root == 0);
    assert(actual_to_user_id == 3);
    assert(null_vk_hash == 42);
    assert(recursive_vk_hash == 77);
    assert(inner_vk_hash == 99);
}
