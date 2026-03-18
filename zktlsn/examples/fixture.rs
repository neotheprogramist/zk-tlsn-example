#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;
#[path = "support/onchain_settlement.rs"]
mod onchain_settlement;
#[path = "support/recursive_batch.rs"]
mod recursive_batch;
#[path = "support/settlement.rs"]
mod settlement_support;

use anyhow::{Context, Result};
use zktlsn::{
    NoirProverInputs, compile_attestation_package, generate_settlement_bundle_from_inputs,
};

const SETTLEMENT_FIXTURE_TXS: &[(u64, u64, u64, [u8; 16])] = &[
    (
        1,
        3,
        25,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ),
    (
        2,
        3,
        10,
        [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
    ),
    (3, 3, 15, [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]),
];

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    zktlsn::ensure_cli_toolchain().context("failed to validate nargo/bb CLI toolchain")?;
    compile_attestation_package().context("failed to compile attestation package")?;

    let to_user_id = SETTLEMENT_FIXTURE_TXS[0].1;
    let attestation_proofs = SETTLEMENT_FIXTURE_TXS
        .iter()
        .map(|(tx_id, to_user_id, amount, blinder)| {
            let inputs = NoirProverInputs::from_transfer(*tx_id, *to_user_id, *amount, *blinder)?;
            let bundle = generate_settlement_bundle_from_inputs(inputs)?;
            Ok(bundle.native_proof)
        })
        .collect::<zktlsn::Result<Vec<_>>>()
        .map_err(anyhow::Error::from)
        .context("failed to generate deterministic attestation proofs")?;

    settlement_support::prepare_settlement_artifacts(&attestation_proofs, to_user_id)
        .context("failed to prepare deterministic settlement artifacts")?;

    println!(
        "Generated settlement fixtures under `evm/testdata/`, generated verifier under `evm/src/generated/`, embedded deployment artifacts under `zktlsn/examples/support/`, and deployed settlement contracts recorded under `target/`."
    );
    Ok(())
}
