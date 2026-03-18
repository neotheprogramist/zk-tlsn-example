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
        use super::generate_settlement_bundle;

        #[test]
        fn settlement_bundle_rejects_empty_proof_list() {
            let proofs = Vec::new();
            let error =
                generate_settlement_bundle(&proofs, 3).expect_err("empty settlement should fail");
            assert!(error.to_string().contains("at least one attestation proof"));
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
