use std::{path::Path, sync::Arc};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use smol::fs;

use crate::{errors::QuicConfigError, tls::generate_self_signed_cert};

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub struct TestQuicConfig {
    pub server_config: quinn::ServerConfig,
    pub client_config: quinn::ClientConfig,
    pub cert_bytes: Vec<u8>,
}

async fn parse_pem_async(path: &Path) -> Result<Vec<u8>, QuicConfigError> {
    let parsed =
        pem::parse(fs::read_to_string(path).await?).map_err(|error| QuicConfigError::PemParse {
            path: path.display().to_string(),
            details: error.to_string(),
        })?;
    Ok(parsed.contents().to_vec())
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
        fs::write(
            cert_path,
            pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes.clone())),
        )
        .await?;
        fs::write(
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
        .with_safe_default_protocol_versions()
        .map_err(|error| QuicConfigError::InvalidConfig(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], PrivateKeyDer::Pkcs8(key_bytes.into()))
        .map_err(|error| QuicConfigError::InvalidConfig(error.to_string()))?;
    server_crypto.alpn_protocols = alpn.clone();

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(cert.clone())
        .map_err(|error| QuicConfigError::InvalidConfig(error.to_string()))?;
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()
        .map_err(|error| QuicConfigError::InvalidConfig(error.to_string()))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = alpn;

    let server_crypto = QuicServerConfig::try_from(server_crypto)
        .map_err(|error| QuicConfigError::InvalidConfig(error.to_string()))?;
    let client_crypto = QuicClientConfig::try_from(client_crypto)
        .map_err(|error| QuicConfigError::InvalidConfig(error.to_string()))?;

    Ok(TestQuicConfig {
        server_config: quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
        client_config: quinn::ClientConfig::new(Arc::new(client_crypto)),
        cert_bytes,
    })
}
