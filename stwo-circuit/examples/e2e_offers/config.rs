use alloy::primitives::Address;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct AppState {
    #[arg(long, env = "RPC_URL", default_value = "http://127.0.0.1:8545")]
    pub rpc_url: String,
    #[arg(long, env = "VERIFIER_ADDRESS")]
    pub verifier_address: Address,
    #[arg(long, env = "PRIVACY_POOL_ADDRESS")]
    pub privacy_pool_address: Address,
    #[arg(long, env = "TOKEN_ADDRESS")]
    pub token_address: Address,
    #[arg(long, env = "OFFER_AMOUNT")]
    pub offer_amount: u32,
    #[arg(
        long,
        env = "POOL_OWNER_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub owner_private_key: String,
    #[arg(long, env = "DEPOSIT_SECRET", default_value_t = 12345u32)]
    pub deposit_secret: u32,
    #[arg(long, env = "DEPOSIT_NULLIFIER", default_value_t = 67890u32)]
    pub deposit_nullifier: u32,
    #[arg(long, env = "DEPOSIT_AMOUNT", default_value_t = 100u32)]
    pub deposit_amount: u32,
    #[arg(long, env = "GAS_LIMIT", default_value_t = 12_000_000_000_000u64)]
    pub gas_limit: u64,
    #[arg(long, env = "MAX_FEE_PER_GAS", default_value_t = 2_000_000_000u128)]
    pub max_fee_per_gas: u128,
    #[arg(
        long,
        env = "MAX_PRIORITY_FEE_PER_GAS",
        default_value_t = 1_000_000_000u128
    )]
    pub max_priority_fee_per_gas: u128,
}

impl AppState {
    pub fn from_env() -> Self {
        Self::parse()
    }
}
