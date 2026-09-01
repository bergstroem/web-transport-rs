use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Buf;
use tokio::io::AsyncWrite;

use crate::{ez, StreamError};

/// A stream that can be used to send bytes.
///
/// This wrapper is mainly needed for error codes.
/// WebTransport uses u32 error codes and they're mapped in a reserved HTTP/3 error space.
pub struct SendStream {
    inner: ez::SendStream,
}

impl SendStream {
    pub(super) fn new(inner: ez::SendStream) -> Self {
        Self { inner }
    }

    /// Write some data to the stream, returning the size written.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, StreamError> {
        self.inner.write(buf).await.map_err(Into::into)
    }

    /// Write data from a buffer to the stream, returning the size written.
    pub async fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Result<usize, StreamError> {
        self.inner.write_buf(buf).await.map_err(Into::into)
    }

    /// Write all of the data to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        self.inner.write_all(buf).await.map_err(Into::into)
    }

    /// Write all data from a buffer to the stream.
    pub async fn write_buf_all<B: Buf>(&mut self, buf: &mut B) -> Result<(), StreamError> {
        self.inner.write_buf_all(buf).await.map_err(Into::into)
    }

    /// Mark the stream as finished, such that no more data can be written.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().map_err(Into::into)
    }

    /// Set the priority of this stream.
    ///
    /// Lower priority values are sent first. Defaults to 0.
    pub fn set_priority(&mut self, order: u8) {
        self.inner.set_priority(order)
    }

    /// Abruptly reset the stream with the provided error code.
    ///
    /// This is a u32 with WebTransport because it shares the error space with HTTP/3.
    pub fn reset(&mut self, code: u32) {
        let code = web_transport_proto::error_to_http3(code);
        self.inner.reset(code)
    }

    /// Wait until the stream has been stopped and return the error code.
    pub async fn closed(&mut self) -> Result<(), StreamError> {
        self.inner.closed().await.map_err(Into::into)
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        // Send a FIN instead of a RESET_STREAM, matching the other backends.
        // A reset here would discard the WebTransport header written by `open_uni`/`open_bi`,
        // hiding the stream from the peer entirely instead of surfacing an error.
        if !self.inner.is_finished().unwrap_or(true) {
            let _ = self.inner.finish();
        }
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let inner = std::pin::pin!(&mut self.inner);
        inner.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = std::pin::pin!(&mut self.inner);
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let inner = std::pin::pin!(&mut self.inner);
        inner.poll_shutdown(cx)
    }
}

impl web_transport_trait::SendStream for SendStream {
    type Error = StreamError;

    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.write(buf).await
    }

    fn set_priority(&mut self, order: u8) {
        self.set_priority(order)
    }

    fn reset(&mut self, code: u32) {
        self.reset(code)
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        self.finish()
    }

    async fn closed(&mut self) -> Result<(), Self::Error> {
        self.closed().await
    }
}
