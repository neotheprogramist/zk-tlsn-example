use std::{fs, process::Command};

use serde_json::Value;

use crate::{
    NoirProverInputs,
    recursive::{field_word_to_u64, parse_hex_field_word},
    repo_root,
    test_fixtures::cli_test_lock,
};

mod settlement_support {
    use crate as zktlsn;

    include!("../examples/support/recursive_batch.rs");

    #[cfg(test)]
    mod tests {
        use crate::{
            TicketSigner,
            recursive::field_word_hex,
            test_fixtures::{cli_test_lock, load_settlement_fixture},
        };

        use super::{MAX_SETTLEMENT_TRANSFERS, generate_settlement_bundle, settlement_prover_toml};

        #[test]
        fn settlement_bundle_rejects_empty_ticket_lists() {
            let tickets = Vec::new();
            let error =
                generate_settlement_bundle(&tickets).expect_err("empty settlement should fail");
            assert!(error.to_string().contains("at least one signed ticket"));
        }

        #[test]
        fn settlement_bundle_rejects_more_than_four_tickets() {
            let signer = TicketSigner::from_env_or_default().expect("load signer");
            let tickets = (0..=MAX_SETTLEMENT_TRANSFERS)
                .map(|index| {
                    signer
                        .sign_ticket(index as u64 + 1, 3, 1)
                        .expect("sign ticket")
                })
                .collect::<Vec<_>>();

            let error =
                generate_settlement_bundle(&tickets).expect_err("oversized settlement should fail");
            assert!(error.to_string().contains("at most 4 transfers"));
        }

        #[test]
        fn settlement_bundle_rejects_mixed_destinations() {
            let signer = TicketSigner::from_env_or_default().expect("load signer");
            let first = signer.sign_ticket(1, 3, 25).expect("sign ticket");
            let second = signer.sign_ticket(2, 4, 10).expect("sign ticket");

            let error = generate_settlement_bundle(&[first, second])
                .expect_err("mixed destination settlement should fail");
            assert!(error.to_string().contains("same to_user_id"));
        }

        #[test]
        fn settlement_bundle_rejects_total_overflow() {
            let signer = TicketSigner::from_env_or_default().expect("load signer");
            let first = signer.sign_ticket(1, 3, u64::MAX).expect("sign ticket");
            let second = signer.sign_ticket(2, 3, 1).expect("sign ticket");

            let error = generate_settlement_bundle(&[first, second])
                .expect_err("overflow settlement should fail");
            assert!(error.to_string().contains("overflow"));
        }

        #[test]
        fn settlement_bundle_matches_fixture_total_and_root() {
            let _guard = cli_test_lock().lock().expect("lock CLI fixture generation");
            let fixture = load_settlement_fixture();
            let bundle =
                generate_settlement_bundle(&fixture.tickets).expect("generate settlement bundle");

            assert_eq!(bundle.state.total_amount, fixture.total_amount);
            assert_eq!(
                field_word_hex(&bundle.state.transfers_root),
                fixture.transfers_root
            );
            assert_eq!(bundle.state.to_user_id, fixture.to_user_id);
            assert_eq!(
                bundle.keccak_proof.public_inputs_hex(),
                fixture.public_inputs
            );
        }

        #[test]
        fn settlement_padding_slot_is_disabled_in_generated_inputs() {
            let fixture = load_settlement_fixture();
            let signer = TicketSigner::from_env_or_default().expect("load signer");
            let padding_ticket = signer.sign_padding_ticket().expect("build padding ticket");
            let mut slot_tickets = fixture.tickets.clone();
            while slot_tickets.len() < MAX_SETTLEMENT_TRANSFERS {
                slot_tickets.push(padding_ticket.clone());
            }

            let toml = settlement_prover_toml(&fixture.tickets, &slot_tickets);
            assert!(toml.contains("enabled = [true, true, true, false]"));
            assert!(toml.contains("tx_ids = [\"1\", \"2\", \"3\", \"0\"]"));
            assert!(toml.contains("to_user_ids = [\"3\", \"3\", \"3\", \"0\"]"));
            assert!(toml.contains("amounts = [\"25\", \"10\", \"15\", \"0\"]"));
        }
    }
}

#[test]
fn noir_inputs_roundtrip_from_transfer() {
    let inputs = NoirProverInputs::from_transfer(
        1,
        3,
        25,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    )
    .expect("build inputs");

    assert_eq!(inputs.tx_id, 1);
    assert_eq!(inputs.to_user_id, 3);
    assert_eq!(inputs.amount, 25);
    assert_eq!(inputs.attestation, "00000000010000000003000000000025");
}

#[test]
fn field_hex_helpers_roundtrip() {
    let word =
        parse_hex_field_word("0x0000000000000000000000000000000000000000000000000000000000000019")
            .expect("parse field");
    assert_eq!(
        field_word_to_u64("0x0000000000000000000000000000000000000000000000000000000000000019")
            .expect("field to u64"),
        25
    );
    assert_eq!(word[31], 25);
}

#[test]
fn settlement_verifier_runtime_size_stays_within_eip_170_limit() {
    let _guard = cli_test_lock().lock().expect("lock forge build");
    let status = Command::new("forge")
        .arg("build")
        .current_dir(repo_root())
        .status()
        .expect("run forge build");
    assert!(status.success(), "forge build should succeed");

    let artifact_path =
        repo_root().join("out/SettlementHonkVerifier.sol/SettlementHonkVerifier.json");
    let artifact = fs::read_to_string(&artifact_path).expect("read settlement verifier artifact");
    let artifact_json: Value = serde_json::from_str(&artifact).expect("decode settlement artifact");
    let bytecode = artifact_json["deployedBytecode"]["object"]
        .as_str()
        .expect("deployed bytecode object");
    let runtime_hex = bytecode.strip_prefix("0x").unwrap_or(bytecode);
    let runtime_size = runtime_hex.len() / 2;

    assert!(
        runtime_size <= 24_576,
        "SettlementHonkVerifier runtime size {runtime_size} exceeds the EIP-170 limit"
    );
}
