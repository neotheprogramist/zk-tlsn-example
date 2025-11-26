use std::{fs, path::Path, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{errors::TlsConfigError, tls::generate_self_signed_cert};

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
    pem::parse(&content)
        .map_err(|e| {
            TlsConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ))
        })
        .map(|p| p.contents().to_vec())
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
