use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::Deserialize;

use crate::{
    HONK_FIELD_BYTES, Proof, SignedTransferTicket, cli::read_field_words_from_bytes,
    parse_hex_field_word, repo_root,
};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AttestationFixture {
    pub(crate) tx_id: u64,
    pub(crate) to_user_id: u64,
    pub(crate) amount: u64,
    pub(crate) attestation: String,
    pub(crate) attestation_blinder: Vec<u8>,
    pub(crate) attestation_committed_hash: Vec<u8>,
    pub(crate) public_inputs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SettlementFixture {
    pub(crate) tickets: Vec<SignedTransferTicket>,
    pub(crate) total_amount: u64,
    pub(crate) transfers_root: String,
    pub(crate) to_user_id: u64,
    pub(crate) public_inputs: Vec<String>,
}

static CLI_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn cli_test_lock() -> &'static Mutex<()> {
    &CLI_TEST_LOCK
}

pub(crate) fn load_attestation_fixture() -> AttestationFixture {
    read_json_fixture("fixture.json")
}

pub(crate) fn load_settlement_fixture() -> SettlementFixture {
    read_json_fixture("settlement_fixture.json")
}

pub(crate) fn load_attestation_proof_from_fixture() -> Proof {
    Proof {
        verification_key: Vec::new(),
        proof: read_fixture_bytes("proof.bin"),
        public_inputs: read_field_words_from_bytes(
            &read_fixture_bytes("public_inputs.bin"),
            "evm/testdata/public_inputs.bin",
        )
        .expect("read attestation fixture public inputs"),
    }
}

pub(crate) fn load_settlement_public_inputs_from_fixture() -> Vec<[u8; HONK_FIELD_BYTES]> {
    read_field_words_from_bytes(
        &read_fixture_bytes("settlement_public_inputs.bin"),
        "evm/testdata/settlement_public_inputs.bin",
    )
    .expect("read settlement fixture public inputs")
}

pub(crate) fn parse_fixture_public_inputs(hex_words: &[String]) -> Vec<[u8; HONK_FIELD_BYTES]> {
    hex_words
        .iter()
        .map(|word| parse_hex_field_word(word).expect("parse fixture field word"))
        .collect()
}

fn read_json_fixture<T>(name: &str) -> T
where
    T: for<'de> Deserialize<'de>,
{
    let path = fixture_path(name);
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!("failed to decode {}: {error}", path.display());
    })
}

fn read_fixture_bytes(name: &str) -> Vec<u8> {
    let path = fixture_path(name);
    fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join(Path::new("evm/testdata")).join(name)
}
