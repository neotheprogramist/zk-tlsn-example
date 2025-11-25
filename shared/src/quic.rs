use std::{path::Path, sync::Arc};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use smol::fs;

use crate::tls::generate_self_signed_cert;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub struct TestQuicConfig {
    pub server_config: quinn::ServerConfig,
    pub client_config: quinn::ClientConfig,
    pub cert_bytes: Vec<u8>,
}

pub async fn get_or_create_test_quic_config(cert_path: &Path, key_path: &Path) -> TestQuicConfig {
    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        // Load existing certificate and key
        let cert_pem = fs::read_to_string(cert_path).await.unwrap();
        let key_pem = fs::read_to_string(key_path).await.unwrap();

        // Parse PEM format
        let cert_bytes = pem::parse(&cert_pem).unwrap().contents().to_vec();

        let key_bytes = pem::parse(&key_pem).unwrap().contents().to_vec();

        (cert_bytes, key_bytes)
    } else {
        // Generate new certificate and key
        let tls_cert = generate_self_signed_cert().unwrap();
        let cert_bytes = tls_cert.cert.der().to_vec();
        let key_bytes = tls_cert.key_pair.serialize_der();

        // Save to files in PEM format
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes.clone()));
        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", key_bytes.clone()));

        fs::write(cert_path, cert_pem).await.unwrap();
        fs::write(key_path, key_pem).await.unwrap();

        (cert_bytes, key_bytes)
    };

    // Build rustls configs
    let key = PrivateKeyDer::Pkcs8(key_bytes.into());
    let cert = CertificateDer::from(cert_bytes.clone());

    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut server_crypto = ServerConfig::builder_with_provider(crypto_provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).unwrap(),
    ));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert.clone()).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    TestQuicConfig {
        server_config,
        client_config,
        cert_bytes,
    }
}
