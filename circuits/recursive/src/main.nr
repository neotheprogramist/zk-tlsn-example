mod generated_constants;

global MAX_SETTLEMENT_TRANSFERS: u32 = 4;
global SIGNATURE_BYTES: u32 = 64;
global TICKET_MESSAGE_BYTES: u32 = 40;

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

fn ticket_domain_separator() -> [u8; 16] {
    [122, 107, 116, 108, 115, 110, 45, 116, 105, 99, 107, 101, 116, 45, 118, 49]
}

fn ticket_message_hash(tx_id: Field, to_user_id: Field, amount: Field) -> [u8; 32] {
    let _tx_id_u64 = field_to_u64(tx_id);
    let _to_user_id_u64 = field_to_u64(to_user_id);
    let _amount_u64 = field_to_u64(amount);

    let tx_id_bytes: [u8; 8] = tx_id.to_be_bytes();
    let to_user_id_bytes: [u8; 8] = to_user_id.to_be_bytes();
    let amount_bytes: [u8; 8] = amount.to_be_bytes();
    let mut input: [u8; TICKET_MESSAGE_BYTES] = [0; TICKET_MESSAGE_BYTES];
    let domain = ticket_domain_separator();

    for i in 0..16 {
        input[i] = domain[i];
    }
    for i in 0..8 {
        input[16 + i] = tx_id_bytes[i];
        input[24 + i] = to_user_id_bytes[i];
        input[32 + i] = amount_bytes[i];
    }

    std::hash::blake3(input)
}

fn verify_ticket_signature(tx_id: Field, to_user_id: Field, amount: Field, signature: [u8; SIGNATURE_BYTES]) {
    let message_hash = ticket_message_hash(tx_id, to_user_id, amount);
    let valid_signature = std::ecdsa_secp256k1::verify_signature(
        generated_constants::TICKET_SIGNER_PUBKEY_X,
        generated_constants::TICKET_SIGNER_PUBKEY_Y,
        signature,
        message_hash,
    );
    assert(valid_signature, "invalid settlement ticket signature");
}

fn main(
    enabled: [bool; MAX_SETTLEMENT_TRANSFERS],
    tx_ids: [Field; MAX_SETTLEMENT_TRANSFERS],
    to_user_ids: [Field; MAX_SETTLEMENT_TRANSFERS],
    amounts: [Field; MAX_SETTLEMENT_TRANSFERS],
    signatures: [[u8; SIGNATURE_BYTES]; MAX_SETTLEMENT_TRANSFERS],
) -> pub (Field, Field, Field) {
    let mut total_amount = 0;
    let mut transfers_root = 0;
    let mut batch_to_user_id = 0;
    let mut seen_ticket = false;

    for i in 0..MAX_SETTLEMENT_TRANSFERS {
        let tx_id = tx_ids[i];
        let to_user_id = to_user_ids[i];
        let amount = amounts[i];
        let signature = signatures[i];

        verify_ticket_signature(tx_id, to_user_id, amount, signature);

        if enabled[i] {
            assert(tx_id != 0, "enabled slot must use non-zero tx_id");
            assert(amount != 0, "enabled slot must use non-zero amount");

            if seen_ticket {
                assert(batch_to_user_id == to_user_id, "to_user_id mismatch");
            } else {
                batch_to_user_id = to_user_id;
                seen_ticket = true;
            }

            total_amount = checked_total(total_amount, amount);
            transfers_root = next_transfers_root(transfers_root, tx_id, amount);
        } else {
            assert(tx_id == 0, "disabled slot must use zero tx_id");
            assert(to_user_id == 0, "disabled slot must use zero to_user_id");
            assert(amount == 0, "disabled slot must use zero amount");
            assert(signature == generated_constants::PADDING_SIGNATURE, "disabled slot signature mismatch");
        }
    }

    assert(seen_ticket, "settlement requires at least one enabled ticket");
    (total_amount, transfers_root, batch_to_user_id)
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
