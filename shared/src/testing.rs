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

/// Get or create a test TLS config with certificate persistence
///
/// This function checks if certificate and key files exist at the given paths.
/// If they exist, it loads them. If not, it generates new ones and saves them.
/// This ensures all processes (prover, verifier, server) use the same certificate.
pub fn get_or_create_test_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<TestTlsConfig, TlsConfigError> {
    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        // Load existing certificate and key
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;

        // Parse PEM format
        let cert_bytes = pem::parse(&cert_pem)
            .map_err(|e| {
                TlsConfigError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse cert PEM: {}", e),
                ))
            })?
            .contents()
            .to_vec();

        let key_bytes = pem::parse(&key_pem)
            .map_err(|e| {
                TlsConfigError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse key PEM: {}", e),
                ))
            })?
            .contents()
            .to_vec();

        (cert_bytes, key_bytes)
    } else {
        // Generate new certificate and key
        let tls_cert = generate_self_signed_cert()?;
        let cert_bytes = tls_cert.cert.der().to_vec();
        let key_bytes = tls_cert.key_pair.serialize_der();

        // Save to files in PEM format
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes.clone()));
        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", key_bytes.clone()));

        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, key_pem)?;

        (cert_bytes, key_bytes)
    };

    // Build rustls configs
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
