use std::ops::Deref;

use thiserror::Error;

use dquic::prelude::{Connection, StreamId, StreamReader, StreamWriter};
use dquic::qbase::error::Error as QuicError;
use web_transport_proto::{ConnectRequest, ConnectResponse, VarInt};

#[derive(Error, Debug, Clone)]
pub enum ConnectError {
    #[error("quic stream was closed early")]
    UnexpectedEnd,

    #[error("protocol error: {0}")]
    ProtoError(#[from] web_transport_proto::ConnectError),

    #[error("connection error: {0}")]
    ConnectionError(#[from] QuicError),

    #[error("http error status: {0}")]
    ErrorStatus(http::StatusCode),

    #[error("server returned protocol not in request: {0}")]
    ProtocolMismatch(String),
}

/// Convert a dquic [`StreamId`] into the WebTransport session ID (a [`VarInt`]).
pub(crate) fn session_id(stream_id: StreamId) -> VarInt {
    VarInt::try_from(u64::from(stream_id)).expect("stream id out of varint range")
}

/// An HTTP/3 CONNECT request that has been received but not yet responded to.
pub struct Connecting {
    pub request: ConnectRequest,

    pub(crate) session_id: VarInt,
    pub(crate) send: StreamWriter,
    pub(crate) recv: StreamReader,
}

impl Connecting {
    /// Accept the bidirectional stream carrying the client's CONNECT request.
    pub async fn accept(conn: &Connection) -> Result<Self, ConnectError> {
        let (sid, (mut recv, send)) = conn.accept_bi_stream().await?;

        let request = web_transport_proto::ConnectRequest::read(&mut recv).await?;
        tracing::debug!(?request, "received CONNECT request");

        Ok(Self {
            request,
            session_id: session_id(sid),
            send,
            recv,
        })
    }

    /// Send a response to the client, establishing the session.
    pub async fn respond(
        mut self,
        response: impl Into<ConnectResponse>,
    ) -> Result<Connected, ConnectError> {
        let response = response.into();

        // Validate that our protocol was in the client's request.
        if let Some(protocol) = &response.protocol {
            if !self.request.protocols.contains(protocol) {
                return Err(ConnectError::ProtocolMismatch(protocol.clone()));
            }
        }

        tracing::debug!(?response, "sending CONNECT response");
        response.write(&mut self.send).await?;
        // dquic buffers stream writes; flush so the response reaches the peer promptly even though
        // nothing else drives this stream afterwards (the proto helper does not flush).
        {
            use tokio::io::AsyncWriteExt;
            let _ = self.send.flush().await;
        }

        Ok(Connected {
            request: self.request,
            response,
            session_id: self.session_id,
            send: self.send,
            recv: self.recv,
        })
    }

    pub async fn reject(self, status: http::StatusCode) -> Result<(), ConnectError> {
        use tokio::io::AsyncWriteExt;
        let mut connect = self.respond(status).await?;
        let _ = connect.send.shutdown().await;
        Ok(())
    }
}

impl Deref for Connecting {
    type Target = ConnectRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

pub struct Connected {
    pub request: ConnectRequest,
    pub response: ConnectResponse,

    pub(crate) session_id: VarInt,
    pub(crate) send: StreamWriter,
    pub(crate) recv: StreamReader,
}

impl Connected {
    /// Open a new WebTransport session on the given connection for the given request.
    pub async fn open(
        conn: &Connection,
        request: impl Into<ConnectRequest>,
    ) -> Result<Self, ConnectError> {
        let request = request.into();

        let (sid, (mut recv, mut send)) = conn
            .open_bi_stream()
            .await?
            .ok_or(ConnectError::UnexpectedEnd)?;

        tracing::debug!(?request, "sending CONNECT request");
        request.write(&mut send).await?;

        let response = web_transport_proto::ConnectResponse::read(&mut recv).await?;
        tracing::debug!(?response, "received CONNECT response");

        if response.status != http::StatusCode::OK {
            return Err(ConnectError::ErrorStatus(response.status));
        }

        if let Some(protocol) = &response.protocol {
            if !request.protocols.contains(protocol) {
                return Err(ConnectError::ProtocolMismatch(protocol.clone()));
            }
        }

        Ok(Self {
            request,
            response,
            session_id: session_id(sid),
            send,
            recv,
        })
    }

    /// The session ID is the stream ID of the CONNECT request.
    pub fn session_id(&self) -> VarInt {
        self.session_id
    }
}
