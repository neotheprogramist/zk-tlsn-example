use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// SmolExecutor implements hyper's Executor trait using smol's runtime
/// with task tracking and wait capabilities
#[derive(Clone, Debug)]
pub struct SmolExecutor {
    task_count: Arc<AtomicUsize>,
    accepting_tasks: Arc<AtomicBool>,
}

impl SmolExecutor {
    pub fn new() -> Self {
        Self {
            task_count: Arc::new(AtomicUsize::new(0)),
            accepting_tasks: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Wait for all spawned tasks to complete
    /// This method blocks new task creation and waits until all tasks finish
    pub async fn wait(&self) {
        // Stop accepting new tasks
        self.accepting_tasks.store(false, Ordering::SeqCst);

        // Wait until all tasks complete
        while self.task_count.load(Ordering::SeqCst) > 0 {
            smol::Timer::after(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Get the current number of active tasks
    pub fn active_tasks(&self) -> usize {
        self.task_count.load(Ordering::SeqCst)
    }

    /// Check if executor is accepting new tasks
    pub fn is_accepting_tasks(&self) -> bool {
        self.accepting_tasks.load(Ordering::SeqCst)
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
        // Don't spawn new tasks if we're shutting down
        if !self.accepting_tasks.load(Ordering::SeqCst) {
            return;
        }

        // Increment task counter
        self.task_count.fetch_add(1, Ordering::SeqCst);

        let task_count = Arc::clone(&self.task_count);

        smol::spawn(async move {
            // Execute the future
            fut.await;

            // Decrement task counter when done
            task_count.fetch_sub(1, Ordering::SeqCst);
        })
        .detach();
    }
}
