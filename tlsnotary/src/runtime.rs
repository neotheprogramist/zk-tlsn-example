use std::{future::Future, pin::Pin};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub trait Runtime: Send + Sync + 'static {
    fn spawn_detached(&self, future: BoxFuture<()>);
}

#[cfg(not(target_arch = "wasm32"))]
pub struct SmolRuntime;

#[cfg(not(target_arch = "wasm32"))]
impl Runtime for SmolRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        smol::spawn(future).detach();
    }
}

#[cfg(target_arch = "wasm32")]
pub struct WasmRuntime;

#[cfg(target_arch = "wasm32")]
impl Runtime for WasmRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        wasm_bindgen_futures::spawn_local(future);
    }
}
