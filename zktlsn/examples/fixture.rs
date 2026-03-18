#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;
#[path = "support/onchain_settlement.rs"]
mod onchain_settlement;
#[path = "support/recursive_batch.rs"]
mod recursive_batch;
#[path = "support/settlement.rs"]
mod settlement_support;

use anyhow::{Context, Result};
use zktlsn::TicketSigner;

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

    let signer =
        TicketSigner::from_env_or_default().context("failed to load verifier ticket signer")?;
    let tickets = SETTLEMENT_FIXTURE_TXS
        .iter()
        .map(|(tx_id, to_user_id, amount, _blinder)| {
            signer.sign_ticket(*tx_id, *to_user_id, *amount)
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)
        .context("failed to build deterministic settlement tickets")?;

    settlement_support::prepare_settlement_artifacts(&tickets)
        .context("failed to prepare deterministic settlement artifacts")?;

    println!(
        "Generated settlement fixtures under `evm/testdata/`, generated verifier under `evm/src/generated/`, embedded deployment artifacts under `zktlsn/examples/support/`, and deployed settlement contracts recorded under `target/`."
    );
    Ok(())
}
