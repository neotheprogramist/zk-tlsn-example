use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{errors::TlsConfigError, tls::generate_self_signed_cert};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_tls_config() {
        let config = create_test_tls_config().unwrap();
        assert!(Arc::strong_count(&config.server_config) == 1);
        assert!(Arc::strong_count(&config.client_config) == 1);
    }
}
