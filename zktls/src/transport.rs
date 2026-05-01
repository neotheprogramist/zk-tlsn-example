use std::{
    future::Future,
    pin::Pin,
    slice,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;

// ─── Runtime abstraction ───────────────────────────────────────────────────

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

// ─── futures <-> hyper I/O bridge ──────────────────────────────────────────

pin_project! {
    #[derive(Debug)]
    pub struct FuturesIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> FuturesIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> hyper::rt::Write for FuturesIo<T>
where
    T: futures::AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}

impl<T> hyper::rt::Read for FuturesIo<T>
where
    T: futures::AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // PROOF: buf_slice is passed to poll_read which by contract only writes into it.
        // Converting &mut [MaybeUninit<u8>] to &mut [u8] is sound because poll_read never
        // reads from the buffer.
        let buf_slice = unsafe {
            slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
        };

        let n = match futures::AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
            Poll::Ready(Ok(n)) => n,
            other => return other.map_ok(|_| ()),
        };

        // PROOF: n bytes were just written by poll_read above into the buffer region
        // backed by the ReadBufCursor's uninitialised memory.
        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}
