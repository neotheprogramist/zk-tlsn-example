//! Thin WASM bindings for `zktlsn_core`.

#![cfg(target_arch = "wasm32")]

mod error;
mod io;
mod prover;
mod runtime;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

pub use prover::Prover;

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
