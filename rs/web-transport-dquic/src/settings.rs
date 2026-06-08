use futures::try_join;
use thiserror::Error;

use dquic::prelude::{Connection, StreamReader, StreamWriter};
use dquic::qbase::error::Error as QuicError;

#[derive(Error, Debug, Clone)]
pub enum SettingsError {
    #[error("quic stream was closed early")]
    UnexpectedEnd,

    #[error("protocol error: {0}")]
    ProtoError(#[from] web_transport_proto::SettingsError),

    #[error("WebTransport is not supported")]
    WebTransportUnsupported,

    #[error("connection error: {0}")]
    ConnectionError(#[from] QuicError),
}

/// Holds the HTTP/3 control streams open for the lifetime of the session.
pub struct Settings {
    #[allow(dead_code)]
    send: StreamWriter,

    #[allow(dead_code)]
    recv: StreamReader,
}

impl Settings {
    /// Perform the H3 SETTINGS handshake by sending and receiving SETTINGS frames.
    pub async fn connect(conn: &Connection) -> Result<Self, SettingsError> {
        let send = Self::open(conn);
        let recv = Self::accept(conn);

        // Run both concurrently until one errors or they both complete.
        let (send, recv) = try_join!(send, recv)?;
        Ok(Self { send, recv })
    }

    async fn accept(conn: &Connection) -> Result<StreamReader, SettingsError> {
        let (_sid, mut recv) = conn.accept_uni_stream().await?;

        let settings = web_transport_proto::Settings::read(&mut recv).await?;
        tracing::debug!(?settings, "received SETTINGS frame");

        if settings.supports_webtransport() == 0 {
            return Err(SettingsError::WebTransportUnsupported);
        }

        Ok(recv)
    }

    async fn open(conn: &Connection) -> Result<StreamWriter, SettingsError> {
        let mut settings = web_transport_proto::Settings::default();
        settings.enable_webtransport(1);

        tracing::debug!(?settings, "sending SETTINGS frame");

        let (_sid, mut send) = conn
            .open_uni_stream()
            .await?
            .ok_or(SettingsError::UnexpectedEnd)?;
        settings.write(&mut send).await?;

        Ok(send)
    }
}
