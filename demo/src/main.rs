use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use demo::{
    CommonCli,
    browser::{self, ServiceConfig},
    ledger::{self, DemoServerConfig, TransferRequest},
    settlement::{SettlementArgs, prepare_settlement_artifacts, run_settlement},
    tls::{TestQuicConfig, get_or_create_test_quic_config, load_test_cert_bytes},
    transport::{self, DemoConnectionConfig, create_transfer},
};
use quinn::Endpoint;
use tokio::net::lookup_host;
use tracing::{error, info};
use zktlsn_core::zk::{NoirProverInputs, prove_attestation_from_inputs};

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
#[command(
    name = "zktlsn",
    about = "zk-tlsn driver: server | service | verifier | settle | fixture"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Demo HTTPS ledger (long-running). Used by both flows.
    Server(ServerArgs),
    /// Browser-facing WebTransport host (long-running). Used by Flow 1.
    Service(ServiceArgs),
    /// QUIC TLSN verifier (long-running). Used by Flow 2.
    Verifier(VerifierArgs),
    /// Run the 3-transfer settlement batch: attest, aggregate, submit on-chain.
    Settle(SettleArgs),
    /// Generate deterministic settlement fixtures and deploy settlement contracts.
    Fixture(FixtureArgs),
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[arg(long, env = "ZKTLSN_SERVER_LISTEN_ADDR")]
    listen_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVER_CERT_PATH")]
    cert_path: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVER_KEY_PATH")]
    key_path: PathBuf,
}

#[derive(Debug, Args)]
struct ServiceArgs {
    #[arg(long, env = "ZKTLSN_SERVICE_LISTEN_ADDR")]
    listen_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVICE_CERT_DIR", default_value = ".data/service")]
    cert_dir: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVICE_ASSET_DIR", default_value = "demo/assets")]
    asset_dir: PathBuf,
    #[arg(
        long,
        env = "ZKTLSN_SERVICE_TEMPLATE_DIR",
        default_value = "demo/templates"
    )]
    template_dir: PathBuf,
    #[arg(long, env = "ZKTLSN_SERVER_ADDR")]
    server_addr: String,
    #[arg(long, env = "ZKTLSN_SERVER_NAME", default_value = "localhost")]
    server_name: String,
    #[arg(long, env = "ZKTLSN_SERVER_CERT_PATH")]
    server_cert_path: PathBuf,
    #[arg(long, env = "ZKTLSN_FROM_USER", default_value = "alice")]
    from_user: String,
    #[arg(long, env = "ZKTLSN_TO_USER", default_value = "treasury")]
    to_user: String,
    #[arg(long, env = "ZKTLSN_TRANSFER_AMOUNT", default_value_t = 25)]
    transfer_amount: u64,
}

#[derive(Debug, Args)]
struct VerifierArgs {
    #[arg(long, env = "ZKTLSN_VERIFIER_ADDR")]
    listen_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_QUIC_CERT_PATH")]
    cert_path: String,
    #[arg(long, env = "ZKTLSN_QUIC_KEY_PATH")]
    key_path: String,
}

#[derive(Debug, Args)]
struct SettleArgs {
    #[command(flatten)]
    common: CommonCli,
    #[arg(long, env = "ZKTLSN_BATCH_FROM_USERS", num_args = 1.., value_delimiter = ',')]
    from_users: Vec<String>,
    #[arg(long, env = "ZKTLSN_BATCH_TO_USERS", num_args = 1.., value_delimiter = ',')]
    to_users: Vec<String>,
    #[arg(long, env = "ZKTLSN_BATCH_AMOUNTS", num_args = 1.., value_delimiter = ',')]
    amounts: Vec<u64>,
}

#[derive(Debug, Args)]
struct FixtureArgs {
    #[arg(long, env = "ZKTLSN_ANVIL_RPC_URL")]
    anvil_rpc_url: String,
    #[arg(long, env = "ZKTLSN_ANVIL_PRIVATE_KEY")]
    anvil_private_key: String,
}

fn main() {
    demo::init_logging().expect("failed to initialize logging");
    let cli = Cli::parse();
    let (name, result) = match cli.command {
        Command::Server(args) => ("server", multi_thread().block_on(run_server(args))),
        Command::Service(args) => ("service", multi_thread().block_on(run_service(args))),
        Command::Verifier(args) => ("verifier", multi_thread().block_on(run_verifier(args))),
        Command::Settle(args) => ("settle", current_thread().block_on(run_settle(args))),
        Command::Fixture(args) => ("fixture", current_thread().block_on(run_fixture(args))),
    };
    if let Err(err) = result {
        error!(error = %format!("{err:#}"), "{name} flow failed");
        std::process::exit(1);
    }
}

fn multi_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to construct multi-thread tokio runtime")
}

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to construct current-thread tokio runtime")
}

async fn run_server(args: ServerArgs) -> Result<()> {
    ledger::serve(DemoServerConfig {
        listen_addr: args.listen_addr,
        cert_path: args.cert_path,
        key_path: args.key_path,
    })
    .await
    .context("failed to run demo server")
}

async fn run_service(args: ServiceArgs) -> Result<()> {
    let (server_host, server_port) = args
        .server_addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("ZKTLSN_SERVER_ADDR `{}` is not host:port", args.server_addr))?;
    let server_port: u16 = server_port
        .parse()
        .context("invalid port in ZKTLSN_SERVER_ADDR")?;

    let allowed_target = lookup_host((server_host, server_port))
        .await
        .context("failed to resolve ZKTLSN_SERVER_ADDR")?
        .next()
        .ok_or_else(|| anyhow!("failed to resolve {}", args.server_addr))?;

    let server_cert_der = load_test_cert_bytes(&args.server_cert_path)
        .context("failed to load server certificate")?;
    let server_cert_der_hex = hex::encode(&server_cert_der);

    let demo_cfg = DemoConnectionConfig {
        server_addr: allowed_target,
        server_name: args.server_name.clone(),
        server_cert_path: args.server_cert_path.clone(),
    };
    let transfer = create_transfer(
        &demo_cfg,
        &TransferRequest {
            from_username: args.from_user.clone(),
            to_username: args.to_user.clone(),
            amount: args.transfer_amount,
        },
    )
    .await
    .context("failed to create demo transfer")?;
    info!(
        tx_id = transfer.tx_id,
        from = %transfer.from_username,
        to = %transfer.to_username,
        amount = transfer.amount,
        "service: created demo transfer via demo ledger"
    );

    browser::serve(ServiceConfig {
        listen_addr: args.listen_addr,
        cert_dir: args.cert_dir,
        asset_dir: args.asset_dir,
        template_dir: args.template_dir,
        allowed_target,
        server_host: server_host.to_string(),
        server_name: args.server_name,
        server_cert_der_hex,
        from_user: args.from_user,
        to_user: args.to_user,
        transfer_amount: args.transfer_amount,
        tx_id: transfer.tx_id,
    })
    .await
    .context("failed to run service")?;
    Ok(())
}

async fn run_verifier(args: VerifierArgs) -> Result<()> {
    let TestQuicConfig { server_config, .. } =
        get_or_create_test_quic_config(Path::new(&args.cert_path), Path::new(&args.key_path))
            .await
            .context("failed to load QUIC server config")?;

    let endpoint = Endpoint::server(server_config, args.listen_addr)
        .context("failed to bind QUIC endpoint")?;
    info!("Reliable streams server listening on {}", args.listen_addr);
    transport::serve(endpoint).await;
    Ok(())
}

async fn run_settle(args: SettleArgs) -> Result<()> {
    demo::ensure_attestation_toolchain().context("failed to prepare attestation toolchain")?;
    run_settlement(SettlementArgs {
        server_addr: args.common.tlsn.server_addr,
        server_name: args.common.tlsn.server_name,
        server_cert_path: args.common.tlsn.server_cert_path,
        verifier_addr: args.common.tlsn.verifier_addr,
        verifier_cert_path: args.common.tlsn.verifier_cert_path,
        from_users: args.from_users,
        to_users: args.to_users,
        amounts: args.amounts,
        anvil_rpc_url: args.common.chain.anvil_rpc_url,
        anvil_private_key: args.common.chain.anvil_private_key,
        mint_recipient: args.common.chain.mint_recipient,
    })
    .await
}

async fn run_fixture(args: FixtureArgs) -> Result<()> {
    demo::ensure_attestation_toolchain().context("failed to prepare attestation toolchain")?;
    let to_user_id = SETTLEMENT_FIXTURE_TXS[0].1;
    let attestation_proofs = SETTLEMENT_FIXTURE_TXS
        .iter()
        .map(|(tx_id, to_user_id, amount, blinder)| {
            let inputs = NoirProverInputs::from_transfer(*tx_id, *to_user_id, *amount, *blinder)?;
            let proof = prove_attestation_from_inputs(inputs)?;
            Ok(proof.native_proof)
        })
        .collect::<zktlsn_core::Result<Vec<_>>>()
        .context("failed to generate deterministic attestation proofs")?;

    prepare_settlement_artifacts(
        &attestation_proofs,
        to_user_id,
        &args.anvil_rpc_url,
        &args.anvil_private_key,
    )
    .await
    .context("failed to prepare deterministic settlement artifacts")?;

    println!("Generated runtime settlement state under `.data/`.");
    Ok(())
}
