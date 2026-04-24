use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use quinn::Endpoint;

use crate::proof::{NotarizedFlow, run_attest_only_flow};

pub async fn open_client_endpoint(verifier_cert_path: &Path) -> Result<Endpoint> {
    let client_config = crate::tls::load_test_quic_client_config(verifier_cert_path)
        .await
        .context("failed to load QUIC client configuration")?;
    let mut endpoint = Endpoint::client("[::]:0".parse().context("invalid client bind address")?)
        .context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

pub async fn connect_and_attest(
    endpoint: &Endpoint,
    verifier_addr: SocketAddr,
    server_addr: SocketAddr,
    server_name: &str,
    server_cert_path: &Path,
    tx_id: u64,
) -> Result<NotarizedFlow> {
    let connection = endpoint
        .connect(verifier_addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;
    run_attest_only_flow(
        tokio::io::join(recv, send),
        server_addr,
        server_name,
        server_cert_path,
        tx_id,
    )
    .await
}
