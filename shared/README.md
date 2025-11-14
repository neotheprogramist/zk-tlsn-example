# Shared

Shared utilities for TLS certificate generation and testing.

## Features

- **In-memory certificate generation**: Create ECDSA P-256 certificates for localhost
- **Test TLS configuration**: Build ready-to-use TLS configs for integration tests
- **Type-safe errors**: Error handling using `thiserror`

## Usage

### Generating a self-signed certificate

```rust
use shared::generate_self_signed_cert;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls_cert = generate_self_signed_cert()?;

    // Access as PEM strings
    let cert_pem = tls_cert.cert.pem();
    let key_pem = tls_cert.key_pair.serialize_pem();

    // Or access as DER bytes
    let cert_der = tls_cert.cert.der();
    let key_der = tls_cert.key_pair.serialize_der();

    Ok(())
}
```

### Creating test TLS configuration

```rust
use shared::create_test_tls_config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = create_test_tls_config()?;

    // Use config.server_config and config.client_config

    Ok(())
}
```

## API

### Types

- `TlsCertificate`: Contains `cert` (Certificate) and `key_pair` (KeyPair) objects
  - Use `.cert.pem()` or `.cert.der()` for certificate data
  - Use `.key_pair.serialize_pem()` or `.key_pair.serialize_der()` for key data
- `TestTlsConfig`: Contains `server_config` and `client_config` (Arc<rustls::*Config>)
- `CertificateError`: Certificate generation errors
- `TlsConfigError`: TLS configuration errors

### Functions

- `generate_self_signed_cert() -> Result<SelfSignedCertificate, CertificateError>`: Generate certificate objects in memory
- `create_test_tls_config() -> Result<TestTlsConfig, TlsConfigError>`: Create TLS configuration for testing

## Certificate Details

- **Algorithm**: ECDSA with P-256 curve
- **Subject**: CN=localhost
- **SANs**: localhost, 127.0.0.1, ::1
- **Validity**: 10 years

## Testing

```bash
cargo test -p shared
```
