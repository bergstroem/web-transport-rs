use thiserror::Error;

use dquic::qbase::error::Error as QuicError;
use dquic::qrecovery::streams::error::StreamError;
use web_transport_proto::error_from_http3;

use crate::{ConnectError, SettingsError};

/// An error returned when connecting to a WebTransport endpoint.
#[derive(Error, Debug, Clone)]
pub enum ClientError {
    #[error("unexpected end of stream")]
    UnexpectedEnd,

    #[error("connection error: {0}")]
    Connection(#[from] QuicError),

    #[error("failed to exchange h3 settings: {0}")]
    SettingsError(#[from] SettingsError),

    #[error("failed to exchange h3 connect: {0}")]
    HttpError(#[from] ConnectError),

    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),

    #[error("failed to build endpoint: {0}")]
    Build(String),

    #[error("failed to connect: {0}")]
    Connect(String),

    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Errors returned by [`crate::Session`], split based on whether they are underlying QUIC errors
/// or WebTransport errors.
#[derive(Clone, Error, Debug)]
pub enum SessionError {
    #[error("connection error: {0}")]
    ConnectionError(QuicError),

    #[error("webtransport error: {0}")]
    WebTransportError(#[from] WebTransportError),

    #[error("send datagram error: {0}")]
    SendDatagram(#[from] SendDatagramError),

    #[error("datagrams not enabled")]
    DatagramUnsupported,

    #[error("locally closed")]
    LocallyClosed,
}

impl From<QuicError> for SessionError {
    fn from(e: QuicError) -> Self {
        if let QuicError::App(app) = &e {
            // An application close carries an HTTP/3 error code, but the reason on the wire is
            // also available. The WebTransport reason (if any) arrives via the
            // CloseWebTransportSession capsule, which the background task records separately.
            if let Some(code) = error_from_http3(app.error_code()) {
                return WebTransportError::Closed(code, app.reason().to_string()).into();
            }
        }
        SessionError::ConnectionError(e)
    }
}

/// An error sending an application datagram.
#[derive(Clone, Error, Debug)]
pub enum SendDatagramError {
    #[error("datagram larger than peer's transport limits")]
    TooLarge,

    #[error("datagrams are not supported by the peer")]
    Unsupported,
}

/// An error reading/writing the WebTransport stream header, or a session-level close.
#[derive(Clone, Error, Debug)]
pub enum WebTransportError {
    #[error("closed: code={0} reason={1}")]
    Closed(u32, String),

    #[error("unknown session")]
    UnknownSession,

    #[error("stream error: {0}")]
    StreamError(StreamError),
}

impl From<StreamError> for WebTransportError {
    fn from(e: StreamError) -> Self {
        WebTransportError::StreamError(e)
    }
}

/// An error when writing to [`crate::SendStream`].
#[derive(Clone, Error, Debug)]
pub enum WriteError {
    #[error("STOP_SENDING: {0}")]
    Stopped(u32),

    #[error("invalid STOP_SENDING: {0}")]
    InvalidStopped(u64),

    #[error("session error: {0}")]
    SessionError(#[from] SessionError),

    #[error("stream closed")]
    ClosedStream,
}

impl From<StreamError> for WriteError {
    fn from(e: StreamError) -> Self {
        match e {
            StreamError::Reset(reset) => match error_from_http3(reset.error_code()) {
                Some(code) => WriteError::Stopped(code),
                None => WriteError::InvalidStopped(reset.error_code()),
            },
            StreamError::Connection(error) => WriteError::SessionError(error.into()),
            StreamError::EosSent => WriteError::ClosedStream,
        }
    }
}

/// An error when reading from [`crate::RecvStream`].
#[derive(Clone, Error, Debug)]
pub enum ReadError {
    #[error("session error: {0}")]
    SessionError(#[from] SessionError),

    #[error("RESET_STREAM: {0}")]
    Reset(u32),

    #[error("invalid RESET_STREAM: {0}")]
    InvalidReset(u64),

    #[error("stream closed")]
    ClosedStream,
}

impl From<StreamError> for ReadError {
    fn from(e: StreamError) -> Self {
        match e {
            StreamError::Reset(reset) => match error_from_http3(reset.error_code()) {
                Some(code) => ReadError::Reset(code),
                None => ReadError::InvalidReset(reset.error_code()),
            },
            StreamError::Connection(error) => ReadError::SessionError(error.into()),
            StreamError::EosSent => ReadError::ClosedStream,
        }
    }
}

/// dquic streams expose tokio's `AsyncRead`/`AsyncWrite`, which surface a [`std::io::Error`]
/// wrapping the underlying [`StreamError`]. Recover the typed error when possible.
impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        match e.downcast::<StreamError>() {
            Ok(stream) => stream.into(),
            Err(_) => ReadError::ClosedStream,
        }
    }
}

/// An error returned when accepting a new WebTransport session on the server.
#[derive(Error, Debug, Clone)]
pub enum ServerError {
    #[error("unexpected end of stream")]
    UnexpectedEnd,

    #[error("connection error: {0}")]
    Connection(#[from] QuicError),

    #[error("failed to exchange h3 settings: {0}")]
    SettingsError(#[from] SettingsError),

    #[error("failed to exchange h3 connect: {0}")]
    ConnectError(#[from] ConnectError),

    #[error("failed to build endpoint: {0}")]
    Build(String),

    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

impl web_transport_trait::Error for SessionError {
    fn session_error(&self) -> Option<(u32, String)> {
        if let SessionError::WebTransportError(WebTransportError::Closed(code, reason)) = self {
            return Some((*code, reason.to_string()));
        }
        None
    }
}

impl web_transport_trait::Error for WriteError {
    fn session_error(&self) -> Option<(u32, String)> {
        if let WriteError::SessionError(e) = self {
            return e.session_error();
        }
        None
    }

    fn stream_error(&self) -> Option<u32> {
        match self {
            WriteError::Stopped(code) => Some(*code),
            _ => None,
        }
    }
}

impl web_transport_trait::Error for ReadError {
    fn session_error(&self) -> Option<(u32, String)> {
        if let ReadError::SessionError(e) = self {
            return e.session_error();
        }
        None
    }

    fn stream_error(&self) -> Option<u32> {
        match self {
            ReadError::Reset(code) => Some(*code),
            _ => None,
        }
    }
}
