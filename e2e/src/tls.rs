use std::{fs, path::Path, sync::Arc};

use chrono::Datelike;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::fs as tokio_fs;

use crate::error::TlsFixtureError;

pub const ALPN_HTTP: &[&[u8]] = &[b"h2", b"http/1.1"];
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const CERT_LIFETIME_DAYS: i64 = 3650;

pub struct TestTlsConfig {
    pub server_config: Arc<rustls::ServerConfig>,
    pub client_config: Arc<rustls::ClientConfig>,
    pub cert_bytes: Vec<u8>,
}

pub struct TestQuicConfig {
    pub server_config: quinn::ServerConfig,
    pub client_config: quinn::ClientConfig,
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

fn parse_pem(path: &Path) -> Result<Vec<u8>, TlsFixtureError> {
    Ok(pem::parse(fs::read_to_string(path)?)?.contents().to_vec())
}

async fn parse_pem_async(path: &Path) -> Result<Vec<u8>, TlsFixtureError> {
    Ok(pem::parse(tokio_fs::read_to_string(path).await?)?
        .contents()
        .to_vec())
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

async fn ensure_parent_dir_async(path: &Path) -> Result<(), TlsFixtureError> {
    let parent = path.parent().ok_or_else(|| {
        TlsFixtureError::Io(std::io::Error::other(format!(
            "path {} is missing a parent directory",
            path.display()
        )))
    })?;
    tokio_fs::create_dir_all(parent).await?;
    Ok(())
}

pub fn load_test_cert_bytes(cert_path: &Path) -> Result<Vec<u8>, TlsFixtureError> {
    parse_pem(cert_path)
}

pub fn load_test_client_tls_config(
    cert_path: &Path,
) -> Result<Arc<rustls::ClientConfig>, TlsFixtureError> {
    let cert = CertificateDer::from(parse_pem(cert_path)?);
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert)?;

    let mut client_config = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols = ALPN_HTTP.iter().map(|&x| x.into()).collect();

    Ok(Arc::new(client_config))
}

pub fn get_or_create_test_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<TestTlsConfig, TlsFixtureError> {
    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        (parse_pem(cert_path)?, parse_pem(key_path)?)
    } else {
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

        (cert_bytes, key_bytes)
    };

    let key = PrivateKeyDer::Pkcs8(key_bytes.into());
    let cert = CertificateDer::from(cert_bytes.clone());
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut server_config = rustls::ServerConfig::builder_with_provider(crypto_provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    server_config.alpn_protocols = ALPN_HTTP.iter().map(|&x| x.into()).collect();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert.clone())?;

    let mut client_config = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols = ALPN_HTTP.iter().map(|&x| x.into()).collect();

    Ok(TestTlsConfig {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
        cert_bytes,
    })
}

pub async fn load_test_quic_client_config(
    cert_path: &Path,
) -> Result<quinn::ClientConfig, TlsFixtureError> {
    let cert = CertificateDer::from(parse_pem_async(cert_path).await?);
    let crypto = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert)?;

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let client_crypto = QuicClientConfig::try_from(client_crypto)?;
    Ok(quinn::ClientConfig::new(Arc::new(client_crypto)))
}

pub async fn get_or_create_test_quic_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<TestQuicConfig, TlsFixtureError> {
    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        (
            parse_pem_async(cert_path).await?,
            parse_pem_async(key_path).await?,
        )
    } else {
        let (cert, key_pair) = build_self_signed(CERT_LIFETIME_DAYS)?;
        let (cert_bytes, key_bytes) = (cert.der().to_vec(), key_pair.serialize_der());
        ensure_parent_dir_async(cert_path).await?;
        ensure_parent_dir_async(key_path).await?;
        tokio_fs::write(
            cert_path,
            pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes.clone())),
        )
        .await?;
        tokio_fs::write(
            key_path,
            pem::encode(&pem::Pem::new("PRIVATE KEY", key_bytes.clone())),
        )
        .await?;
        (cert_bytes, key_bytes)
    };

    let cert = CertificateDer::from(cert_bytes.clone());
    let crypto = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let alpn: Vec<Vec<u8>> = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(crypto.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], PrivateKeyDer::Pkcs8(key_bytes.into()))?;
    server_crypto.alpn_protocols = alpn.clone();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert.clone())?;
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = alpn;

    let server_crypto = QuicServerConfig::try_from(server_crypto)?;
    let client_crypto = QuicClientConfig::try_from(client_crypto)?;

    Ok(TestQuicConfig {
        server_config: quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
        client_config: quinn::ClientConfig::new(Arc::new(client_crypto)),
        cert_bytes,
    })
}
