use anyhow::{Context, Result};
use clap::Parser;
use zktlsn::{NoirProverInputs, prove_attestation_from_inputs};

use e2e::settlement as settlement_support;

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

#[derive(Debug, Parser)]
#[command(about = "Generate deterministic settlement fixtures and deploy settlement contracts")]
struct Cli {
    #[arg(long, env = "ZKTLSN_ANVIL_RPC_URL")]
    anvil_rpc_url: String,
    #[arg(long, env = "ZKTLSN_ANVIL_PRIVATE_KEY")]
    anvil_private_key: String,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    zktlsn::cli::ensure_cli_toolchain().context("failed to validate nargo/bb CLI toolchain")?;
    zktlsn::recursive::compile_attestation_package()
        .context("failed to compile attestation package")?;

    let to_user_id = SETTLEMENT_FIXTURE_TXS[0].1;
    let attestation_proofs = SETTLEMENT_FIXTURE_TXS
        .iter()
        .map(|(tx_id, to_user_id, amount, blinder)| {
            let inputs = NoirProverInputs::from_transfer(*tx_id, *to_user_id, *amount, *blinder)?;
            let proof = prove_attestation_from_inputs(inputs)?;
            Ok(proof.native_proof)
        })
        .collect::<zktlsn::Result<Vec<_>>>()
        .context("failed to generate deterministic attestation proofs")?;

    settlement_support::prepare_settlement_artifacts(
        &attestation_proofs,
        to_user_id,
        &cli.anvil_rpc_url,
        &cli.anvil_private_key,
    )
    .context("failed to prepare deterministic settlement artifacts")?;

    println!("Generated runtime settlement state under `.data/`.");
    Ok(())
}
