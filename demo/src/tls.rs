use std::{fs, path::Path, sync::Arc};

use chrono::Datelike;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsFixtureError {
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    #[error(transparent)]
    PemDecode(#[from] pem::PemError),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

const ALPN_HTTP: &[&[u8]] = &[b"h2", b"http/1.1"];
const CERT_LIFETIME_DAYS: i64 = 3650;

pub struct TestTlsConfig {
    pub server_config: Arc<rustls::ServerConfig>,
    pub cert_bytes: Vec<u8>,
}

pub(crate) fn build_self_signed(
    lifetime_days: i64,
) -> Result<(Certificate, KeyPair), rcgen::Error> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
        SanType::IpAddress(std::net::Ipv6Addr::LOCALHOST.into()),
    ];

    let now = chrono::Utc::now();
    let future = now + chrono::Duration::days(lifetime_days);
    // PROOF: chrono Datelike::month() ∈ [1,12] and day() ∈ [1,31]; both fit u8 by construction.
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after =
        rcgen::date_time_ymd(future.year(), future.month() as u8, future.day() as u8);

    let cert = params.self_signed(&key_pair)?;
    Ok((cert, key_pair))
}

pub fn get_or_create_cert_bytes(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Vec<u8>, TlsFixtureError> {
    let (cert_bytes, _) = load_or_create_cert_key(cert_path, key_path)?;
    Ok(cert_bytes)
}

pub fn get_or_create_test_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<TestTlsConfig, TlsFixtureError> {
    let (cert_bytes, key_bytes) = load_or_create_cert_key(cert_path, key_path)?;
    let key = PrivateKeyDer::Pkcs8(key_bytes.into());
    let cert = CertificateDer::from(cert_bytes.clone());

    let mut server_config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    server_config.alpn_protocols = alpn(ALPN_HTTP);

    Ok(TestTlsConfig {
        server_config: Arc::new(server_config),
        cert_bytes,
    })
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn alpn(protocols: &[&[u8]]) -> Vec<Vec<u8>> {
    protocols.iter().map(|&p| p.to_vec()).collect()
}

fn parse_pem(path: &Path) -> Result<Vec<u8>, TlsFixtureError> {
    Ok(pem::parse(fs::read_to_string(path)?)?.contents().to_vec())
}

fn ensure_parent_dir(path: &Path) -> Result<(), TlsFixtureError> {
    let parent = path.parent().ok_or_else(|| {
        TlsFixtureError::Io(std::io::Error::other(format!(
            "path {} is missing a parent directory",
            path.display()
        )))
    })?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn load_or_create_cert_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<u8>, Vec<u8>), TlsFixtureError> {
    if cert_path.exists() && key_path.exists() {
        return Ok((parse_pem(cert_path)?, parse_pem(key_path)?));
    }

    let (cert, key_pair) = build_self_signed(CERT_LIFETIME_DAYS)?;
    let cert_bytes = cert.der().to_vec();
    let key_bytes = key_pair.serialize_der();

    ensure_parent_dir(cert_path)?;
    ensure_parent_dir(key_path)?;

    fs::write(
        cert_path,
        pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes.clone())),
    )?;
    fs::write(
        key_path,
        pem::encode(&pem::Pem::new("PRIVATE KEY", key_bytes.clone())),
    )?;

    Ok((cert_bytes, key_bytes))
}
