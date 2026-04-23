use std::{future::Future, pin::Pin};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub trait Runtime: Send + Sync + 'static {
    fn spawn_detached(&self, future: BoxFuture<()>);
}

pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        tokio::spawn(future);
    }
}

pub struct SmolRuntime;

impl Runtime for SmolRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        smol::spawn(future).detach();
    }
}
