use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use tokio::io::AsyncReadExt;

use dquic::prelude::{StopSending, StreamReader};

use crate::{app_error, ReadError, SessionError};

/// A stream that can be used to receive bytes. Wraps a dquic [`StreamReader`].
pub struct RecvStream {
    stream: StreamReader,
    error: Arc<OnceLock<SessionError>>,
}

impl RecvStream {
    pub(crate) fn new(stream: StreamReader, error: Arc<OnceLock<SessionError>>) -> Self {
        Self { stream, error }
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: impl Into<ReadError>) -> ReadError {
        let e = e.into();
        if let Some(err) = self.error.get() {
            if matches!(&e, ReadError::SessionError(_)) {
                return ReadError::SessionError(err.clone());
            }
        }
        e
    }

    /// Tell the other end to stop sending data with the given error code.
    ///
    /// This is a `u32` because WebTransport shares the error space with HTTP/3.
    pub fn stop(&mut self, code: u32) {
        self.stream.stop(app_error(code));
    }

    /// Read some data into the buffer, returning the number of bytes read, or `None` on FIN.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        if buf.is_empty() {
            return Ok(Some(0));
        }
        let n = self.stream.read(buf).await.map_err(|e| self.map_error(e))?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(n))
        }
    }

    /// Read the next chunk of data, up to `max` bytes, or `None` on FIN.
    pub async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, ReadError> {
        let mut buf = vec![0u8; max];
        let n = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| self.map_error(e))?;
        if n == 0 {
            Ok(None)
        } else {
            buf.truncate(n);
            Ok(Some(buf.into()))
        }
    }
}

impl web_transport_trait::RecvStream for RecvStream {
    type Error = ReadError;

    fn stop(&mut self, code: u32) {
        Self::stop(self, code);
    }

    async fn read(&mut self, dst: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Self::read(self, dst).await
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, Self::Error> {
        Self::read_chunk(self, max).await
    }

    async fn closed(&mut self) -> Result<(), Self::Error> {
        // Drain any remaining data until the stream is finished or reset.
        let mut buf = [0u8; 1024];
        loop {
            match self
                .stream
                .read(&mut buf)
                .await
                .map_err(|e| self.map_error(e))?
            {
                0 => return Ok(()),
                _ => continue,
            }
        }
    }
}
