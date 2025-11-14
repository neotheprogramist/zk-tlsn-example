use std::future::Future;

/// SmolExecutor implements hyper's Executor trait using smol's runtime
#[derive(Clone, Debug)]
pub struct SmolExecutor;

impl SmolExecutor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SmolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> hyper::rt::Executor<F> for SmolExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        smol::spawn(fut).detach();
    }
}
