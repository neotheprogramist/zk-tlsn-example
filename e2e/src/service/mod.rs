pub mod cert;
pub mod connect;
pub mod headers;
pub mod pages;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use salvo::prelude::{Listener, QuinnListener, Router, Server, StaticDir, TcpListener};
use salvo::{affix_state, conn::rustls::RustlsConfig};

use cert::{CertError, ServiceCertificate};
use connect::ProxyConfig;
use pages::PageState;

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
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(
        "required wasm artifact missing at {0}: run the wasm build before starting the service"
    )]
    MissingWasm(PathBuf),
}

pub async fn serve(config: ServiceConfig) -> Result<(), ServeError> {
    let wasm_path = config.asset_dir.join("wasm").join("tlsnotary_bg.wasm");
    if !wasm_path.exists() {
        return Err(ServeError::MissingWasm(wasm_path));
    }

    let certificate = ServiceCertificate::load_or_create(&config.cert_dir)?;
    let listen_authority = format_authority(&config.listen_addr);

    let page_state = Arc::new(PageState {
        cert_hash_hex: certificate.fingerprint_hex.clone(),
        connect_url: format!("https://{listen_authority}/connect"),
        server_host: config.server_host.clone(),
        server_port: config.allowed_target.port(),
        server_name: config.server_name.clone(),
        from_user: config.from_user.clone(),
        to_user: config.to_user.clone(),
        transfer_amount: config.transfer_amount,
        tx_id: config.tx_id,
        server_cert_der_hex: config.server_cert_der_hex.clone(),
    });

    let proxy_config = Arc::new(ProxyConfig {
        allowed_target: config.allowed_target,
        allowed_host: config.server_host.clone(),
    });

    tracing::info!(
        listen = %listen_authority,
        cert_sha256 = %certificate.fingerprint_hex,
        allowed_target = %config.allowed_target,
        "service: listening on https://{listen_authority}/"
    );

    let rustls_config: RustlsConfig = certificate.rustls_config();
    let acceptor = QuinnListener::new(rustls_config.clone(), config.listen_addr)
        .join(TcpListener::new(config.listen_addr).rustls(rustls_config))
        .bind()
        .await;

    let router = build_router(page_state, proxy_config, config.asset_dir);
    Server::new(acceptor).serve(router).await;
    Ok(())
}

fn build_router(
    page_state: Arc<PageState>,
    proxy_config: Arc<ProxyConfig>,
    asset_dir: PathBuf,
) -> Router {
    Router::new()
        .hoop(headers::cross_origin_isolation)
        .hoop(affix_state::inject(page_state))
        .hoop(affix_state::inject(proxy_config))
        .get(pages::render_index)
        .push(Router::with_path("cert-hash").get(pages::render_cert_hash))
        .push(Router::with_path("connect").goal(connect::handle))
        .push(Router::with_path("assets/{**}").get(StaticDir::new([asset_dir])))
}

fn format_authority(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(_) => addr.to_string(),
        SocketAddr::V6(addr_v6) => {
            format!("[{}]:{}", addr_v6.ip(), addr_v6.port())
        }
    }
}
