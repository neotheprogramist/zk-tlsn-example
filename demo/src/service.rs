use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use askama::Template;
use salvo::{
    Error as SalvoError, affix_state, async_trait,
    conn::rustls::{Keycert, RustlsConfig},
    handler,
    http::{
        StatusCode, StatusError,
        header::{HeaderName, HeaderValue},
    },
    prelude::{
        Depot, FlowCtrl, Listener, QuinnListener, Request, Response, Router, Server, StaticDir,
        TcpListener, Writer,
    },
    writing::Text,
};
use sha2::{Digest, Sha256};

use crate::{connect::ProxyConfig, tls::build_self_signed};

const CERT_LIFETIME_DAYS: i64 = 14;

// ─── Public types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub listen_addr: SocketAddr,
    pub cert_dir: PathBuf,
    pub asset_dir: PathBuf,
    pub template_dir: PathBuf,
    pub allowed_target: SocketAddr,
    pub server_host: String,
    pub server_name: String,
    pub server_cert_der_hex: String,
    pub from_user: String,
    pub to_user: String,
    pub transfer_amount: u64,
    pub tx_id: u64,
    pub vault_tx_id: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pem(#[from] pem::PemError),
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),
    #[error(
        "required wasm artifact missing at {0}: run the wasm build before starting the service"
    )]
    MissingWasm(PathBuf),
    #[error("page state missing from depot")]
    PageStateMissing,
    #[error("template render failed: {0}")]
    Render(#[from] askama::Error),
    #[error(transparent)]
    Salvo(#[from] SalvoError),
}

pub async fn serve(config: ServiceConfig) -> Result<(), ServeError> {
    for required in [
        config.asset_dir.join("wasm").join("zktls_bg.wasm"),
        config.asset_dir.join("wasm").join("zkp_bg.wasm"),
        config.asset_dir.join("wasm").join("vault_bg.wasm"),
    ] {
        if !required.exists() {
            return Err(ServeError::MissingWasm(required));
        }
    }

    let ServiceCertificate {
        cert_pem,
        key_pem,
        fingerprint_hex,
    } = ServiceCertificate::load_or_create(&config.cert_dir)?;
    let listen_authority = format_authority(&config.listen_addr);

    let proxy_config = Arc::new(ProxyConfig {
        allowed_target: config.allowed_target,
        allowed_host: config.server_host.clone(),
        server_name: config.server_name.clone(),
        to_username: config.to_user.clone(),
    });

    let page_state = Arc::new(PageState {
        cert_hash_hex: fingerprint_hex,
        server_host: config.server_host,
        server_port: config.allowed_target.port(),
        server_name: config.server_name,
        from_user: config.from_user,
        to_user: config.to_user,
        transfer_amount: config.transfer_amount,
        tx_id: config.tx_id,
        server_cert_der_hex: config.server_cert_der_hex,
        vault_tx_id: config.vault_tx_id,
    });

    tracing::info!(
        listen = %listen_authority,
        cert_sha256 = %page_state.cert_hash_hex,
        allowed_target = %config.allowed_target,
        "demo.service.listening"
    );

    let rustls_config = RustlsConfig::new(
        Keycert::new()
            .cert(cert_pem.as_bytes())
            .key(key_pem.as_bytes()),
    );
    let acceptor = QuinnListener::new(rustls_config.clone(), config.listen_addr)
        .join(TcpListener::new(config.listen_addr).rustls(rustls_config))
        .bind()
        .await;

    let wasm_dir = config.asset_dir.join("wasm");
    let router = Router::new()
        .hoop(cross_origin_isolation)
        .hoop(affix_state::inject(page_state))
        .hoop(affix_state::inject(proxy_config))
        .get(render_landing)
        .push(Router::with_path("zktls").get(render_zktls))
        .push(Router::with_path("zkp").get(render_zkp))
        .push(Router::with_path("vault").get(render_vault))
        .push(Router::with_path("cert-hash").get(render_cert_hash))
        .push(Router::with_path("favicon.ico").get(empty_no_content))
        .push(Router::with_path("connect").goal(crate::connect::handle))
        .push(
            Router::with_path("assets/wasm/{**}")
                .hoop(wasm_cache_headers)
                .get(StaticDir::new([wasm_dir])),
        )
        .push(Router::with_path("assets/{**}").get(StaticDir::new([config.asset_dir])));

    Server::new(acceptor).serve(router).await;
    Ok(())
}

fn format_authority(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(_) => addr.to_string(),
        SocketAddr::V6(addr_v6) => format!("[{}]:{}", addr_v6.ip(), addr_v6.port()),
    }
}

// ─── Cross-origin isolation headers ────────────────────────────────────────

const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const COEP: HeaderName = HeaderName::from_static("cross-origin-embedder-policy");
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");

/// Emits Cross-Origin-Opener-Policy + Cross-Origin-Embedder-Policy response
/// headers on every request so Chrome treats the service as cross-origin
/// isolated. Required because the wasm prover is built with `+atomics` +
/// `--shared-memory`, which forces the browser to only instantiate the module
/// in a `SharedArrayBuffer`-enabled context.
#[handler]
async fn cross_origin_isolation(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;
    let headers = res.headers_mut();
    headers.insert(COOP, HeaderValue::from_static("same-origin"));
    headers.insert(COEP, HeaderValue::from_static("require-corp"));
    headers.insert(CORP, HeaderValue::from_static("same-origin"));
}

/// Adds long-lived caching for WASM assets so concurrent Worker fetches for
/// spawn.js (spawned by Rayon's thread pool) hit the HTTP cache instead of
/// making new TLS round-trips to Salvo. Without this, 8-16 simultaneous
/// requests can exceed the browser's HTTP/1.1 connection limit (6) and cause
/// ERR:ABORTED → deadlock.
#[handler]
async fn wasm_cache_headers(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;
    res.headers_mut().insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("public, max-age=3600, immutable"),
    );
}

// ─── Self-signed service certificate ───────────────────────────────────────

struct ServiceCertificate {
    cert_pem: String,
    key_pem: String,
    fingerprint_hex: String,
}

impl ServiceCertificate {
    fn load_or_create(data_dir: &Path) -> Result<Self, ServeError> {
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

    fn load_current(cert_path: &Path, key_path: &Path) -> Result<Option<Self>, ServeError> {
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

    fn create() -> Result<Self, ServeError> {
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

// ─── HTML pages ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PageState {
    pub cert_hash_hex: String,
    pub server_host: String,
    pub server_port: u16,
    pub server_name: String,
    pub from_user: String,
    pub to_user: String,
    pub transfer_amount: u64,
    pub tx_id: u64,
    pub server_cert_der_hex: String,
    /// tx_id of the vault-demo seeded transfer (alice → bob) used by the
    /// /vault page's TLSN gate. Distinct from `tx_id` (which the /zktls
    /// page exercises against the alice → treasury transfer).
    pub vault_tx_id: u64,
}

#[derive(Template)]
#[template(path = "zktls.html")]
struct ZktlsTemplate<'a> {
    cert_hash_hex: &'a str,
    server_host: &'a str,
    server_port: u16,
    server_name: &'a str,
    from_user: &'a str,
    to_user: &'a str,
    transfer_amount: u64,
    tx_id: u64,
    server_cert_der_hex: &'a str,
}

#[derive(Template)]
#[template(path = "landing.html")]
struct LandingTemplate;

#[derive(Template)]
#[template(path = "zkp.html")]
struct ZkpTemplate;

#[derive(Template)]
#[template(path = "vault.html")]
struct VaultTemplate<'a> {
    cert_hash_hex: &'a str,
    server_host: &'a str,
    server_port: u16,
    server_name: &'a str,
    server_cert_der_hex: &'a str,
    vault_tx_id: u64,
}

#[async_trait]
impl Writer for ServeError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        tracing::error!(error = %self, "demo.service.request.failed");
        res.render(StatusError::internal_server_error());
    }
}

#[handler]
async fn render_landing(res: &mut Response) -> Result<(), ServeError> {
    let html = LandingTemplate.render()?;
    res.render(Text::Html(html));
    Ok(())
}

#[handler]
async fn render_zkp(res: &mut Response) -> Result<(), ServeError> {
    let html = ZkpTemplate.render()?;
    res.render(Text::Html(html));
    Ok(())
}

#[handler]
async fn render_vault(depot: &mut Depot, res: &mut Response) -> Result<(), ServeError> {
    let state = depot
        .obtain::<Arc<PageState>>()
        .map_err(|_| ServeError::PageStateMissing)?;
    let html = VaultTemplate {
        cert_hash_hex: &state.cert_hash_hex,
        server_host: &state.server_host,
        server_port: state.server_port,
        server_name: &state.server_name,
        server_cert_der_hex: &state.server_cert_der_hex,
        vault_tx_id: state.vault_tx_id,
    }
    .render()?;
    res.render(Text::Html(html));
    Ok(())
}

#[handler]
async fn render_zktls(depot: &mut Depot, res: &mut Response) -> Result<(), ServeError> {
    let state = depot
        .obtain::<Arc<PageState>>()
        .map_err(|_| ServeError::PageStateMissing)?;
    let html = ZktlsTemplate {
        cert_hash_hex: &state.cert_hash_hex,
        server_host: &state.server_host,
        server_port: state.server_port,
        server_name: &state.server_name,
        from_user: &state.from_user,
        to_user: &state.to_user,
        transfer_amount: state.transfer_amount,
        tx_id: state.tx_id,
        server_cert_der_hex: &state.server_cert_der_hex,
    }
    .render()?;
    res.render(Text::Html(html));
    Ok(())
}

#[handler]
async fn empty_no_content(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[handler]
async fn render_cert_hash(depot: &mut Depot, res: &mut Response) -> Result<(), ServeError> {
    let state = depot
        .obtain::<Arc<PageState>>()
        .map_err(|_| ServeError::PageStateMissing)?;
    res.render(Text::Plain(state.cert_hash_hex.clone()));
    Ok(())
}
