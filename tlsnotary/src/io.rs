use core::slice;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;

pin_project! {
    #[derive(Debug)]
    pub(crate) struct FuturesIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> FuturesIo<T> {
    pub(crate) fn new(inner: T) -> Self {
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

#[cfg(target_arch = "wasm32")]
mod wt {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{AsyncRead, AsyncWrite, FutureExt, future::LocalBoxFuture};
    use js_sys::{Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsError, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        ReadableStreamDefaultReader, WebTransportBidirectionalStream, WritableStreamDefaultWriter,
    };

    pub struct WebTransportIo {
        reader: ReadableStreamDefaultReader,
        writer: WritableStreamDefaultWriter,
        read_state: ReadState,
        write_state: WriteState,
        close_state: CloseState,
        leftover: Vec<u8>,
    }

    enum ReadState {
        Idle,
        Pending(LocalBoxFuture<'static, Result<ReadChunk, JsValue>>),
        Eof,
    }

    enum WriteState {
        Idle,
        Pending(LocalBoxFuture<'static, Result<(), JsValue>>),
    }

    enum CloseState {
        Idle,
        Pending(LocalBoxFuture<'static, Result<(), JsValue>>),
        Done,
    }

    enum ReadChunk {
        Data(Vec<u8>),
        End,
    }

    impl WebTransportIo {
        pub fn from_bidi(stream: WebTransportBidirectionalStream) -> Result<Self, JsError> {
            let readable = stream.readable();
            let writable = stream.writable();
            let reader = readable
                .get_reader()
                .dyn_into::<ReadableStreamDefaultReader>()
                .map_err(|_| {
                    JsError::new("WebTransport readable.getReader() returned a non-default reader")
                })?;
            let writer = writable.get_writer().map_err(|err| {
                JsError::new(&format!("WebTransport writable.getWriter failed: {err:?}"))
            })?;
            Ok(Self {
                reader,
                writer,
                read_state: ReadState::Idle,
                write_state: WriteState::Idle,
                close_state: CloseState::Idle,
                leftover: Vec::new(),
            })
        }
    }

    // PROOF: WebTransportIo is only ever constructed and polled inside the Flow 3
    // dedicated Worker. Every JsValue handle it owns (the bidi stream's reader,
    // writer, and the pending LocalBoxFutures) stays on that one worker thread
    // from creation to Drop. The Rust-side `Send` bound required by
    // tlsn::prover::Prover::connect is satisfied vacuously — there is no second
    // thread this type ever reaches.
    unsafe impl Send for WebTransportIo {}
    unsafe impl Sync for WebTransportIo {}

    fn read_chunk(
        reader: ReadableStreamDefaultReader,
    ) -> LocalBoxFuture<'static, Result<ReadChunk, JsValue>> {
        async move {
            let result_promise = reader.read();
            let result = JsFuture::from(result_promise).await?;
            let object: &Object = result.unchecked_ref();
            let done = Reflect::get(object, &JsValue::from_str("done"))?
                .as_bool()
                .ok_or_else(|| JsValue::from_str("WebTransport reader returned non-bool `done`"))?;
            if done {
                return Ok(ReadChunk::End);
            }
            let value = Reflect::get(object, &JsValue::from_str("value"))?;
            let array: Uint8Array = value
                .dyn_into()
                .map_err(|_| JsValue::from_str("WebTransport read chunk was not a Uint8Array"))?;
            let mut buf = vec![0u8; array.length() as usize];
            array.copy_to(&mut buf[..]);
            Ok(ReadChunk::Data(buf))
        }
        .boxed_local()
    }

    fn write_chunk(
        writer: WritableStreamDefaultWriter,
        bytes: Vec<u8>,
    ) -> LocalBoxFuture<'static, Result<(), JsValue>> {
        async move {
            let array = Uint8Array::new_with_length(bytes.len() as u32);
            array.copy_from(&bytes);
            JsFuture::from(writer.write_with_chunk(&array.into())).await?;
            Ok(())
        }
        .boxed_local()
    }

    fn js_to_io_error(err: JsValue) -> std::io::Error {
        std::io::Error::other(format!("WebTransportIo: {err:?}"))
    }

    impl AsyncRead for WebTransportIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = &mut *self;

            if !this.leftover.is_empty() {
                let n = this.leftover.len().min(buf.len());
                buf[..n].copy_from_slice(&this.leftover[..n]);
                this.leftover.drain(..n);
                return Poll::Ready(Ok(n));
            }

            loop {
                match &mut this.read_state {
                    ReadState::Eof => return Poll::Ready(Ok(0)),
                    ReadState::Idle => {
                        this.read_state = ReadState::Pending(read_chunk(this.reader.clone()));
                    }
                    ReadState::Pending(fut) => match fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.read_state = ReadState::Eof;
                            return Poll::Ready(Err(js_to_io_error(err)));
                        }
                        Poll::Ready(Ok(ReadChunk::End)) => {
                            this.read_state = ReadState::Eof;
                            return Poll::Ready(Ok(0));
                        }
                        Poll::Ready(Ok(ReadChunk::Data(mut chunk))) => {
                            this.read_state = ReadState::Idle;
                            let n = chunk.len().min(buf.len());
                            buf[..n].copy_from_slice(&chunk[..n]);
                            if n < chunk.len() {
                                this.leftover = chunk.split_off(n);
                            }
                            return Poll::Ready(Ok(n));
                        }
                    },
                }
            }
        }
    }

    impl AsyncWrite for WebTransportIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = &mut *self;
            loop {
                match &mut this.write_state {
                    WriteState::Idle => {
                        let bytes = buf.to_vec();
                        this.write_state =
                            WriteState::Pending(write_chunk(this.writer.clone(), bytes));
                    }
                    WriteState::Pending(fut) => match fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.write_state = WriteState::Idle;
                            return Poll::Ready(Err(js_to_io_error(err)));
                        }
                        Poll::Ready(Ok(())) => {
                            this.write_state = WriteState::Idle;
                            return Poll::Ready(Ok(buf.len()));
                        }
                    },
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = &mut *self;
            loop {
                match &mut this.close_state {
                    CloseState::Done => return Poll::Ready(Ok(())),
                    CloseState::Idle => {
                        let writer = this.writer.clone();
                        let fut = async move {
                            JsFuture::from(writer.close()).await?;
                            Ok::<_, JsValue>(())
                        }
                        .boxed_local();
                        this.close_state = CloseState::Pending(fut);
                    }
                    CloseState::Pending(fut) => match fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.close_state = CloseState::Done;
                            return Poll::Ready(Err(js_to_io_error(err)));
                        }
                        Poll::Ready(Ok(())) => {
                            this.close_state = CloseState::Done;
                            return Poll::Ready(Ok(()));
                        }
                    },
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wt::WebTransportIo;
