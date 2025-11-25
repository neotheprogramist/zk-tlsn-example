use std::future::Future;

#[derive(Clone, Debug, Default)]
pub struct SmolExecutor {}

impl<F> hyper::rt::Executor<F> for SmolExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        smol::spawn(fut).detach();
    }
}
