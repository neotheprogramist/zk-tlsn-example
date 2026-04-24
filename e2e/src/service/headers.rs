use salvo::handler;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::{Depot, FlowCtrl, Request, Response};

const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const COEP: HeaderName = HeaderName::from_static("cross-origin-embedder-policy");
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");

/// Emits Cross-Origin-Opener-Policy + Cross-Origin-Embedder-Policy response
/// headers on every request so Chrome treats the service as cross-origin
/// isolated. Required because the wasm prover is built with `+atomics` +
/// `--shared-memory`, which forces the browser to only instantiate the module
/// in a `SharedArrayBuffer`-enabled context.
#[handler]
pub async fn cross_origin_isolation(
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
