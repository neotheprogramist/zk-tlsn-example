use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, FutureExt, future::LocalBoxFuture};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, prelude::*};
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

// PROOF: WebTransportIo is constructed and polled inside one dedicated Worker.
// Its JS handles and pending LocalBoxFutures do not cross into another thread.
unsafe impl Send for WebTransportIo {}
unsafe impl Sync for WebTransportIo {}

fn read_chunk(
    reader: ReadableStreamDefaultReader,
) -> LocalBoxFuture<'static, Result<ReadChunk, JsValue>> {
    async move {
        let result = JsFuture::from(reader.read()).await?;
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
        array.copy_to(&mut buf);
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
                    this.write_state =
                        WriteState::Pending(write_chunk(this.writer.clone(), buf.to_vec()));
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
                    this.close_state = CloseState::Pending(
                        async move {
                            JsFuture::from(writer.close()).await?;
                            Ok::<_, JsValue>(())
                        }
                        .boxed_local(),
                    );
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
