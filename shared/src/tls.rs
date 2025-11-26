use chrono::Datelike;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

use crate::errors::CertificateError;

pub struct SelfSignedCertificate {
    pub cert: Certificate,
    pub key_pair: KeyPair,
}

pub fn generate_self_signed_cert() -> Result<SelfSignedCertificate, CertificateError> {
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
    let future = now + chrono::Duration::days(3650);
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after =
        rcgen::date_time_ymd(future.year(), future.month() as u8, future.day() as u8);

    Ok(SelfSignedCertificate {
        cert: params.self_signed(&key_pair)?,
        key_pair,
    })
}
