use anyhow::{Context, Result, anyhow};
use clap::Parser;
use tracing::{info, instrument};

use e2e::{
    bootstrap,
    cli::{TlsnClientCli, TransferCli},
    client::{connect_and_attest, open_client_endpoint},
    demo::{DemoConnectionConfig, create_transfer},
    server::app::{TransferRequest, TransferResponse},
    transcript::log_notarized_flow,
    verifier::VerificationOutcome,
};

#[derive(Debug, Clone, Parser)]
struct Cli {
    #[command(flatten)]
    tlsn: TlsnClientCli,
    #[command(flatten)]
    transfer: TransferCli,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    bootstrap::run_main("notarize", || run(Cli::parse())).await;
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

    let (server_name, commitment_count) = match &flow.verification {
        VerificationOutcome::Success {
            server_name,
            commitment_count,
            ..
        } => (server_name.clone(), *commitment_count),
        VerificationOutcome::Failure { message, .. } => {
            return Err(anyhow!("verifier rejected attestation: {message}"));
        }
    };

    let parsed = parse_http_json_body::<TransferResponse>(&flow.response_text)
        .context("failed to parse notarised HTTP response body")?;

    info!(
        tx_id = transfer.tx_id,
        to_user_id = transfer.to_user_id,
        to_username = %parsed.to_username,
        amount = parsed.amount,
        eligible_for_mint = parsed.eligible_for_mint,
        server_name = %server_name,
        commitment_count,
        "TLSN attestation verified (no ZK proof)"
    );

    let result = serde_json::json!({
        "flow": "notarize",
        "server_name": server_name,
        "to_username": parsed.to_username,
        "amount": parsed.amount,
        "eligible_for_mint": parsed.eligible_for_mint,
        "commitment_count": commitment_count,
    });
    println!("ZKTLSN_RESULT {result}");

    Ok(())
}

fn parse_http_json_body<T: serde::de::DeserializeOwned>(response_text: &str) -> Result<T> {
    let body = response_text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| anyhow!("HTTP response missing header/body separator"))?;
    serde_json::from_str(body.trim()).context("failed to deserialize HTTP body as JSON")
}
