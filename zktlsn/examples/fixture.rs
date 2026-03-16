#[path = "support/batch_settlement.rs"]
mod batch_settlement_support;
#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;
#[path = "support/recursive_batch.rs"]
mod recursive_batch;
#[path = "support/settlement.rs"]
mod settlement_support;

use anyhow::{Context, Result};
use zktlsn::{NoirProverInputs, generate_settlement_bundle_from_inputs};

const FIXTURE_TX_ID: u64 = 1;
const FIXTURE_TO_USER_ID: u64 = 3;
const FIXTURE_AMOUNT: u64 = 25;
const FIXTURE_BLINDER: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const BATCH_FIXTURE_TXS: &[(u64, u64, u64, [u8; 16])] = &[
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
    let srs_path = zktlsn::download_barretenberg_srs_to_cache()
        .context("failed to download cached Barretenberg SRS")?;
    zktlsn::setup_cached_barretenberg_srs().context("failed to setup cached Barretenberg SRS")?;

    let inputs = NoirProverInputs::from_transfer(
        FIXTURE_TX_ID,
        FIXTURE_TO_USER_ID,
        FIXTURE_AMOUNT,
        FIXTURE_BLINDER,
    )
    .context("failed to build deterministic fixture inputs")?;
    let bundle = generate_settlement_bundle_from_inputs(inputs)
        .context("failed to build deterministic settlement bundle")?;
    settlement_support::prepare_settlement_artifacts(&bundle)
        .context("failed to prepare deterministic settlement artifacts")?;
    let batch_inputs = BATCH_FIXTURE_TXS
        .iter()
        .map(|(tx_id, to_user_id, amount, blinder)| {
            NoirProverInputs::from_transfer(*tx_id, *to_user_id, *amount, *blinder)
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)
        .context("failed to build deterministic batch fixture inputs")?;
    batch_settlement_support::prepare_batch_settlement_artifacts(&batch_inputs)
        .context("failed to prepare deterministic batch settlement artifacts")?;

    println!(
        "Downloaded cached Barretenberg SRS to `{}`, generated settlement fixtures under `evm/testdata/`, generated verifiers under `evm/src/generated/`, and embedded deployment artifacts under `zktlsn/examples/support/`.",
        srs_path.display()
    );
    Ok(())
}
