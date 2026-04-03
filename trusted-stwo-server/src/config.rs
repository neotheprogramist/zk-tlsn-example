use clap::Parser;

#[derive(Debug, Parser)]
pub struct AppConfig {
    #[arg(long, env = "TRUSTED_SERVER_ADDR", default_value = "0.0.0.0:8080")]
    pub trusted_server_addr: String,

    #[arg(long, env = "TRUSTED_SERVER_PRIVATE_KEY_HEX")]
    pub trusted_server_private_key_hex: Option<String>,

    #[arg(
        long,
        env = "RUST_LOG",
        default_value = "trusted_stwo_server=info,axum=info"
    )]
    pub rust_log: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self::parse()
    }
}
