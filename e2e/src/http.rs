use anyhow::{Context, Result};
use tlsnotary::{
    CertificateDer, MpcTlsConfig, RootCertStore, ServerName, TlsClientConfig, TlsCommitConfig,
    VerifierConfig, prover::RevealConfig,
};

use crate::verifier::{MAX_RECV_DATA, MAX_SENT_DATA};

pub fn tls_client_config(cert_bytes: Vec<u8>, server_name: &str) -> Result<TlsClientConfig> {
    let server_name = ServerName::Dns(
        server_name
            .to_string()
            .try_into()
            .context("invalid TLS server name")?,
    );
    TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()
        .context("failed to build TLS client config")
}

pub fn tls_commit_config() -> Result<TlsCommitConfig> {
    let mpc = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .context("failed to build MPC-TLS config")?;
    TlsCommitConfig::builder()
        .protocol(mpc)
        .build()
        .context("failed to build TLS commit config")
}

pub fn verifier_config(cert_bytes: Vec<u8>) -> Result<VerifierConfig> {
    VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()
        .context("failed to build verifier config")
}

pub fn balance_request_reveal() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}
