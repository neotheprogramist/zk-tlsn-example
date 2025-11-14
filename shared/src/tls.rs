use chrono::Datelike;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

use crate::errors::CertificateError;

const VALIDITY_DAYS: i64 = 3650;

pub struct SelfSignedCertificate {
    pub cert: Certificate,
    pub key_pair: KeyPair,
}

pub fn generate_self_signed_cert() -> Result<SelfSignedCertificate, CertificateError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let params = build_params()?;
    let cert = params.self_signed(&key_pair)?;

    Ok(SelfSignedCertificate { cert, key_pair })
}

fn build_params() -> Result<CertificateParams, CertificateError> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;

    params.subject_alt_names =
        vec![
            SanType::DnsName("localhost".try_into().map_err(|e| {
                CertificateError::InvalidDateTime(format!("Invalid DNS name: {}", e))
            })?),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ];

    set_validity(&mut params)?;

    Ok(params)
}

fn set_validity(params: &mut CertificateParams) -> Result<(), CertificateError> {
    let now = chrono::Utc::now();
    let future = now + chrono::Duration::days(VALIDITY_DAYS);

    let month = u8::try_from(now.month()).map_err(|_| {
        CertificateError::InvalidDateTime(format!("Invalid month: {}", now.month()))
    })?;
    let day = u8::try_from(now.day())
        .map_err(|_| CertificateError::InvalidDateTime(format!("Invalid day: {}", now.day())))?;
    params.not_before = rcgen::date_time_ymd(now.year(), month, day);

    let future_month = u8::try_from(future.month()).map_err(|_| {
        CertificateError::InvalidDateTime(format!("Invalid month: {}", future.month()))
    })?;
    let future_day = u8::try_from(future.day())
        .map_err(|_| CertificateError::InvalidDateTime(format!("Invalid day: {}", future.day())))?;
    params.not_after = rcgen::date_time_ymd(future.year(), future_month, future_day);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let tls_cert = generate_self_signed_cert().unwrap();

        let cert_pem = tls_cert.cert.pem();
        let key_pem = tls_cert.key_pair.serialize_pem();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(key_pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_certificate_has_valid_der() {
        let tls_cert = generate_self_signed_cert().unwrap();

        let cert_der = tls_cert.cert.der();
        let key_der = tls_cert.key_pair.serialize_der();

        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());
    }
}
