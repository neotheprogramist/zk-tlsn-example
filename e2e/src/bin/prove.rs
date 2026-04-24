use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, instrument};

use e2e::{
    bootstrap,
    cli::{TlsnClientCli, TransferCli},
    client::{connect_and_attest, open_client_endpoint},
    demo::{DemoConnectionConfig, create_transfer},
    server::app::TransferRequest,
    transcript::log_notarized_flow,
    verifier::VerificationOutcome,
};
use zktlsn::{PaddingConfig, extract_committed_hash_from_proof, prove_attestation};

#[derive(Debug, Clone, Parser)]
struct Cli {
    #[command(flatten)]
    tlsn: TlsnClientCli,
    #[command(flatten)]
    transfer: TransferCli,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    bootstrap::run_main("prover", || async {
        bootstrap::ensure_attestation_toolchain()
            .context("failed to prepare attestation toolchain")?;
        run(Cli::parse()).await
    })
    .await;
}

#[instrument(skip(cli))]
async fn run(cli: Cli) -> Result<()> {
    let demo = DemoConnectionConfig {
        server_addr: cli.tlsn.server_addr,
        server_name: cli.tlsn.server_name.clone(),
        server_cert_path: cli.tlsn.server_cert_path.clone(),
    };
    let transfer = create_transfer(
        &demo,
        &TransferRequest {
            from_username: cli.transfer.from_user.clone(),
            to_username: cli.transfer.to_user.clone(),
            amount: cli.transfer.amount,
        },
    )
    .await
    .context("failed to create transfer attestation")?;

    let endpoint = open_client_endpoint(&cli.tlsn.verifier_cert_path).await?;
    let flow = connect_and_attest(
        &endpoint,
        cli.tlsn.verifier_addr,
        cli.tlsn.server_addr,
        &cli.tlsn.server_name,
        &cli.tlsn.server_cert_path,
        transfer.tx_id,
    )
    .await
    .context("failed to complete TLSN attestation flow")?;
    log_notarized_flow(&flow);

    let server_name = match &flow.verification {
        VerificationOutcome::Success { server_name, .. } => server_name.clone(),
        VerificationOutcome::Failure { message, .. } => {
            return Err(anyhow::anyhow!("verifier rejected attestation: {message}"));
        }
    };

    info!(
        tx_id = transfer.tx_id,
        "Generating per-transfer ZK proof via zktlsn::prove_attestation"
    );
    let attestation_proof = prove_attestation(
        &flow.transcript_commitments,
        &flow.transcript_secrets,
        &flow.received_transcript,
        PaddingConfig::new(shared::ATTESTATION_LEN),
    )
    .context("failed to generate attestation ZK proof")?;

    let committed_hash = extract_committed_hash_from_proof(&attestation_proof.native_proof)
        .context("failed to extract committed hash from proof")?;

    info!(
        tx_id = transfer.tx_id,
        to_user_id = transfer.to_user_id,
        amount = cli.transfer.amount,
        proof_len = attestation_proof.native_proof.proof.len(),
        vk_len = attestation_proof.native_proof.verification_key.len(),
        public_inputs_count = attestation_proof.native_proof.public_inputs.len(),
        committed_hash_hex = %hex::encode(committed_hash),
        "Per-transfer attestation ZK proof generated"
    );

    let result = serde_json::json!({
        "flow": "prove",
        "server_name": server_name,
        "tx_id": transfer.tx_id,
        "to_user_id": transfer.to_user_id,
        "to_username": transfer.to_username,
        "amount": cli.transfer.amount,
        "eligible_for_mint": transfer.eligible_for_mint,
        "commitment_count": flow.commitment_count,
        "proof_len": attestation_proof.native_proof.proof.len(),
        "vk_len": attestation_proof.native_proof.verification_key.len(),
        "public_inputs_count": attestation_proof.native_proof.public_inputs.len(),
        "committed_hash": format!("0x{}", hex::encode(committed_hash)),
    });
    println!("ZKTLSN_RESULT {result}");
    Ok(())
}
