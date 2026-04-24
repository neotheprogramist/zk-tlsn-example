use salvo::conn::rustls::{Keycert, RustlsConfig};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

use crate::tls::build_self_signed;

const CERT_LIFETIME_DAYS: i64 = 14;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pem(#[from] pem::PemError),
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),
}

pub struct ServiceCertificate {
    cert_pem: String,
    key_pem: String,
    pub fingerprint_hex: String,
}

impl ServiceCertificate {
    pub fn load_or_create(data_dir: &Path) -> Result<Self, CertError> {
        let cert_path = data_dir.join("cert.pem");
        let key_path = data_dir.join("key.pem");

        if let Some(certificate) = Self::load_current(&cert_path, &key_path)? {
            return Ok(certificate);
        }

        let certificate = Self::create()?;
        std::fs::create_dir_all(data_dir)?;
        std::fs::write(&cert_path, &certificate.cert_pem)?;
        std::fs::write(&key_path, &certificate.key_pem)?;
        Ok(certificate)
    }

    fn load_current(cert_path: &Path, key_path: &Path) -> Result<Option<Self>, CertError> {
        if !cert_path.exists() || !key_path.exists() || certificate_expired(cert_path, key_path) {
            return Ok(None);
        }

        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        let cert_der = pem::parse(&cert_pem)?.into_contents();
        Ok(Some(Self {
            cert_pem,
            key_pem,
            fingerprint_hex: sha256_hex(&cert_der),
        }))
    }

    fn create() -> Result<Self, CertError> {
        let (cert, key) = build_self_signed(CERT_LIFETIME_DAYS)?;
        let cert_der = cert.der().to_vec();
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone()));
        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", key.serialize_der()));

        Ok(Self {
            cert_pem,
            key_pem,
            fingerprint_hex: sha256_hex(&cert_der),
        })
    }

    pub fn rustls_config(&self) -> RustlsConfig {
        RustlsConfig::new(
            Keycert::new()
                .cert(self.cert_pem.as_bytes())
                .key(self.key_pem.as_bytes()),
        )
    }
}

fn certificate_expired(cert_path: &Path, key_path: &Path) -> bool {
    [cert_path, key_path]
        .into_iter()
        .filter_map(|path| std::fs::metadata(path).ok()?.modified().ok())
        .min()
        .and_then(|issued_at| issued_at.elapsed().ok())
        .is_none_or(|age| age >= Duration::from_secs((CERT_LIFETIME_DAYS as u64) * 24 * 60 * 60))
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
