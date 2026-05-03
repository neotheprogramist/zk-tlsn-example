//! Browser-side bindings: wasm-bindgen Prover + Verifier + WebTransport I/O.
//!
//! All items here are gated on `target_arch = "wasm32"` by the parent
//! `lib.rs`. The native build of this crate does not see this module.

mod io;
mod prover;
mod verifier;

pub use prover::Prover;
pub use verifier::Verifier;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::transport::{BoxFuture, Runtime};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub async fn initialize() -> Result<(), JsError> {
    JsFuture::from(web_spawn::start_spawner())
        .await
        .map_err(|err| JsError::new(&format!("web-spawn spawner failed to start: {err:?}")))?;
    Ok(())
}

pub(crate) struct WasmRuntime;

impl Runtime for WasmRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        wasm_bindgen_futures::spawn_local(future);
    }
}
