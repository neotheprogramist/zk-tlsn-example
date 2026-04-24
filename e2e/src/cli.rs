use std::{net::SocketAddr, path::PathBuf};

use alloy::primitives::Address;
use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct TlsnClientCli {
    #[arg(long, env = "ZKTLSN_SERVER_ADDR")]
    pub server_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_SERVER_NAME")]
    pub server_name: String,
    #[arg(long, env = "ZKTLSN_SERVER_CERT_PATH")]
    pub server_cert_path: PathBuf,
    #[arg(long, env = "ZKTLSN_VERIFIER_ADDR")]
    pub verifier_addr: SocketAddr,
    #[arg(long, env = "ZKTLSN_VERIFIER_CERT_PATH")]
    pub verifier_cert_path: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct ChainCli {
    #[arg(long, env = "ZKTLSN_ANVIL_RPC_URL")]
    pub anvil_rpc_url: String,
    #[arg(long, env = "ZKTLSN_ANVIL_PRIVATE_KEY")]
    pub anvil_private_key: String,
    #[arg(long, env = "ZKTLSN_MINT_RECIPIENT")]
    pub mint_recipient: Address,
}

#[derive(Debug, Clone, Args)]
pub struct CommonCli {
    #[command(flatten)]
    pub tlsn: TlsnClientCli,
    #[command(flatten)]
    pub chain: ChainCli,
}

#[derive(Debug, Clone, Args)]
pub struct TransferCli {
    #[arg(long, env = "ZKTLSN_FROM_USER")]
    pub from_user: String,
    #[arg(long, env = "ZKTLSN_TO_USER")]
    pub to_user: String,
    #[arg(long, env = "ZKTLSN_TRANSFER_AMOUNT")]
    pub amount: u64,
}
