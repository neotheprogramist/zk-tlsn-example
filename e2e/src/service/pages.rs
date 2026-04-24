use std::sync::Arc;

use askama::Template;
use salvo::handler;
use salvo::http::StatusError;
use salvo::prelude::{Depot, Request, Response, Writer};
use salvo::writing::Text;
use salvo::{Error as SalvoError, async_trait};

#[derive(Debug, Clone)]
pub struct PageState {
    pub cert_hash_hex: String,
    pub connect_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub server_name: String,
    pub from_user: String,
    pub to_user: String,
    pub transfer_amount: u64,
    pub tx_id: u64,
    pub server_cert_der_hex: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    cert_hash_hex: &'a str,
    connect_url: &'a str,
    server_host: &'a str,
    server_port: u16,
    server_name: &'a str,
    from_user: &'a str,
    to_user: &'a str,
    transfer_amount: u64,
    tx_id: u64,
    server_cert_der_hex: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum PageError {
    #[error("page state missing from depot")]
    StateMissing,
    #[error("template render failed: {0}")]
    Render(#[from] askama::Error),
    #[error(transparent)]
    Salvo(#[from] SalvoError),
}

#[async_trait]
impl Writer for PageError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        tracing::error!(error = %self, "page render failed");
        res.render(StatusError::internal_server_error());
    }
}

#[handler]
pub async fn render_index(depot: &mut Depot, res: &mut Response) -> Result<(), PageError> {
    let state = depot
        .obtain::<Arc<PageState>>()
        .map_err(|_| PageError::StateMissing)?;
    let html = IndexTemplate {
        cert_hash_hex: &state.cert_hash_hex,
        connect_url: &state.connect_url,
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
pub async fn render_cert_hash(depot: &mut Depot, res: &mut Response) -> Result<(), PageError> {
    let state = depot
        .obtain::<Arc<PageState>>()
        .map_err(|_| PageError::StateMissing)?;
    res.render(Text::Plain(state.cert_hash_hex.clone()));
    Ok(())
}
