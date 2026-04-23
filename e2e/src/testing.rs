use std::{fs, path::Path, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{error::TlsConfigError, tls::generate_self_signed_cert};

pub const ALPN_HTTP: &[&[u8]] = &[b"h2", b"http/1.1"];

pub struct TestTlsConfig {
    pub server_config: Arc<rustls::ServerConfig>,
    pub client_config: Arc<rustls::ClientConfig>,
    pub cert_bytes: Vec<u8>,
}

pub fn create_test_tls_config() -> Result<TestTlsConfig, TlsConfigError> {
    let tls_cert = generate_self_signed_cert()?;
    let key = PrivateKeyDer::Pkcs8(tls_cert.key_pair.serialize_der().into());
    let cert = CertificateDer::from(tls_cert.cert.der().to_vec());
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut server_config = rustls::ServerConfig::builder_with_provider(crypto_provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert.clone())?;

    let client_config = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TestTlsConfig {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
        cert_bytes: cert.to_vec(),
    })
}

fn parse_pem(path: &Path) -> Result<Vec<u8>, TlsConfigError> {
    let content = fs::read_to_string(path)?;
    Ok(pem::parse(&content)?.contents().to_vec())
}

fn ensure_parent_dir(path: &Path) -> Result<(), TlsConfigError> {
    let parent = path.parent().ok_or_else(|| {
        TlsConfigError::Io(std::io::Error::other(format!(
            "path {} is missing a parent directory",
            path.display()
        )))
    })?;
    fs::create_dir_all(parent)?;
    Ok(())
}

pub fn load_test_cert_bytes(cert_path: &Path) -> Result<Vec<u8>, TlsConfigError> {
    parse_pem(cert_path)
}

pub fn load_test_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<rustls::ServerConfig>, TlsConfigError> {
    let key = PrivateKeyDer::Pkcs8(parse_pem(key_path)?.into());
    let cert = CertificateDer::from(parse_pem(cert_path)?);
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut server_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_config.alpn_protocols = ALPN_HTTP.iter().map(|&x| x.into()).collect();

    Ok(Arc::new(server_config))
}

pub fn load_test_client_tls_config(
    cert_path: &Path,
) -> Result<Arc<rustls::ClientConfig>, TlsConfigError> {
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
) -> Result<TestTlsConfig, TlsConfigError> {
    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        (parse_pem(cert_path)?, parse_pem(key_path)?)
    } else {
        let tls_cert = generate_self_signed_cert()?;
        let cert_bytes = tls_cert.cert.der().to_vec();
        let key_bytes = tls_cert.key_pair.serialize_der();

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

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tokio::fs as tokio_fs;

use crate::error::QuicConfigError;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub struct TestQuicConfig {
    pub server_config: quinn::ServerConfig,
    pub client_config: quinn::ClientConfig,
    pub cert_bytes: Vec<u8>,
}

async fn parse_pem_async(path: &Path) -> Result<Vec<u8>, QuicConfigError> {
    Ok(pem::parse(tokio_fs::read_to_string(path).await?)?
        .contents()
        .to_vec())
}

async fn ensure_parent_dir_async(path: &Path) -> Result<(), QuicConfigError> {
    let parent = path.parent().ok_or_else(|| {
        QuicConfigError::Io(std::io::Error::other(format!(
            "path {} is missing a parent directory",
            path.display()
        )))
    })?;
    tokio_fs::create_dir_all(parent).await?;
    Ok(())
}

pub fn create_test_quic_config() -> Result<TestQuicConfig, QuicConfigError> {
    let tls_cert = generate_self_signed_cert()?;
    build_test_quic_config(
        tls_cert.cert.der().to_vec(),
        tls_cert.key_pair.serialize_der(),
    )
}

pub async fn load_test_quic_client_config(
    cert_path: &Path,
) -> Result<quinn::ClientConfig, QuicConfigError> {
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
) -> Result<TestQuicConfig, QuicConfigError> {
    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        (
            parse_pem_async(cert_path).await?,
            parse_pem_async(key_path).await?,
        )
    } else {
        let tls_cert = generate_self_signed_cert()?;
        let (cert_bytes, key_bytes) = (
            tls_cert.cert.der().to_vec(),
            tls_cert.key_pair.serialize_der(),
        );
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

    build_test_quic_config(cert_bytes, key_bytes)
}

fn build_test_quic_config(
    cert_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
) -> Result<TestQuicConfig, QuicConfigError> {
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
