use zktlsn_core::transport::{BoxFuture, Runtime};

pub struct WasmRuntime;

impl Runtime for WasmRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        wasm_bindgen_futures::spawn_local(future);
    }
}
