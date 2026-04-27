use http_body_util::Empty;
use hyper::{Method, Request, body::Bytes};
use tlsn::{
    config::{
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
    },
    connection::{DnsName, ServerName},
    webpki::{CertificateDer, RootCertStore},
};

use crate::{
    Error,
    attestation::ATTESTATION_LEN,
    prover::{BodyFieldConfig, KeyValueCommitConfig, RevealConfig},
};

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

pub fn transfer_request(tx_id: u64) -> Result<Request<Empty<Bytes>>, Error> {
    Ok(Request::builder()
        .method(Method::GET)
        .uri(format!("/api/attestations/{tx_id}"))
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::new())?)
}

pub fn transfer_request_reveal() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}

pub fn transfer_response_reveal() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_fields: vec![
            BodyFieldConfig::Quoted(".toUsername".into()),
            BodyFieldConfig::Unquoted(".eligibleForMint".into()),
        ],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![KeyValueCommitConfig::with_padding(
            ".attestation".into(),
            ATTESTATION_LEN,
        )],
    }
}

pub fn transfer_tls_configs(
    server_cert_der: Vec<u8>,
    server_name: &str,
) -> Result<(TlsClientConfig, TlsCommitConfig), Error> {
    let dns = DnsName::try_from(server_name).map_err(|err| Error::DnsInvalid {
        server_name: server_name.to_string(),
        reason: err.to_string(),
    })?;
    let tls_client_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(dns))
        .root_store(RootCertStore {
            roots: vec![CertificateDer(server_cert_der)],
        })
        .build()?;
    let mpc_config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;
    let tls_commit_config = TlsCommitConfig::builder().protocol(mpc_config).build()?;
    Ok((tls_client_config, tls_commit_config))
}
