use std::{
    future::poll_fn,
    io::Cursor,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use dquic::prelude::{Connection, DatagramReader, DatagramWriter, StreamReader, StreamWriter};

use crate::{
    app_error,
    proto::{ConnectRequest, ConnectResponse, Frame, StreamUni, VarInt},
    ClientError, Connected, RecvStream, SendDatagramError, SendStream, SessionError, Settings,
    WebTransportError,
};

/// An established WebTransport session, acting like a QUIC connection.
///
/// WebTransport is layered on top of QUIC:
///   1. Each stream starts with a few bytes identifying the stream type and session ID.
///   2. Error codes are encoded within a reserved HTTP/3 error space.
///   3. Stream IDs may have gaps, used by HTTP/3 transparently to the application.
#[derive(Clone)]
pub struct Session {
    conn: Connection,

    // The session ID, as determined by the stream ID of the CONNECT request.
    session_id: VarInt,

    // Cached headers written in front of each stream/datagram we create.
    header_uni: Vec<u8>,
    header_bi: Vec<u8>,
    header_datagram: Vec<u8>,

    // Keep the settings streams open until the session is dropped.
    #[allow(dead_code)]
    settings: Arc<Settings>,

    // The send side of the CONNECT stream, used to write the CloseWebTransportSession capsule.
    connect_send: Arc<Mutex<Option<StreamWriter>>>,

    // Datagram endpoints, if datagrams were negotiated.
    datagram_writer: Option<DatagramWriter>,
    datagram_reader: Option<Arc<DatagramReader>>,

    // Session error, set once by either local close() or the background task.
    error: Arc<OnceLock<SessionError>>,

    // Signalled to `true` when the session has closed; drives `closed()`.
    closed_rx: watch::Receiver<bool>,

    request: ConnectRequest,
    response: ConnectResponse,
}

impl Session {
    pub(crate) fn new(
        conn: Connection,
        settings: Settings,
        connect: Connected,
        datagram_reader: Option<DatagramReader>,
        datagram_writer: Option<DatagramWriter>,
    ) -> Self {
        let session_id = connect.session_id();

        let mut header_uni = Vec::new();
        StreamUni::WEBTRANSPORT.encode(&mut header_uni);
        session_id.encode(&mut header_uni);

        let mut header_bi = Vec::new();
        Frame::WEBTRANSPORT.encode(&mut header_bi);
        session_id.encode(&mut header_bi);

        let mut header_datagram = Vec::new();
        session_id.encode(&mut header_datagram);

        let error: Arc<OnceLock<SessionError>> = Arc::new(OnceLock::new());
        let (closed_tx, closed_rx) = watch::channel(false);

        let this = Self {
            conn: conn.clone(),
            session_id,
            header_uni,
            header_bi,
            header_datagram,
            settings: Arc::new(settings),
            connect_send: Arc::new(Mutex::new(Some(connect.send))),
            datagram_writer,
            datagram_reader: datagram_reader.map(Arc::new),
            error: error.clone(),
            closed_rx,
            request: connect.request.clone(),
            response: connect.response.clone(),
        };

        // Background task: read capsules from the CONNECT recv stream until it closes.
        tokio::spawn(Self::run_recv(conn, connect.recv, error, closed_tx));

        this
    }

    /// Connect using an established QUIC connection.
    ///
    /// This only works with a brand new QUIC connection using the HTTP/3 ALPN.
    pub async fn connect(
        conn: Connection,
        request: impl Into<ConnectRequest>,
    ) -> Result<Session, ClientError> {
        let request = request.into();

        // Perform the H3 handshake by sending/receiving SETTINGS frames.
        let settings = Settings::connect(&conn).await?;

        // Send the HTTP/3 CONNECT request.
        let connect = Connected::open(&conn, request).await?;

        let (datagram_reader, datagram_writer) = Self::datagrams(&conn).await;

        Ok(Session::new(
            conn,
            settings,
            connect,
            datagram_reader,
            datagram_writer,
        ))
    }

    /// Obtain the datagram reader/writer for a connection, if datagrams were negotiated.
    #[allow(deprecated)]
    pub(crate) async fn datagrams(
        conn: &Connection,
    ) -> (Option<DatagramReader>, Option<DatagramWriter>) {
        let reader = match conn.datagram_reader() {
            Ok(Ok(reader)) => Some(reader),
            _ => None,
        };
        let writer = match conn.datagram_writer().await {
            Ok(Ok(writer)) => Some(writer),
            _ => None,
        };
        (reader, writer)
    }

    // Read capsules from the CONNECT recv stream until it closes, then record the close
    // error and tear down the connection.
    async fn run_recv(
        conn: Connection,
        recv: StreamReader,
        error: Arc<OnceLock<SessionError>>,
        closed_tx: watch::Sender<bool>,
    ) {
        let close_info = Self::read_capsules(recv).await;

        match close_info {
            Some((code, reason)) => {
                let err = WebTransportError::Closed(code, reason);
                let _ = error.set(err.into());
                let _ = conn.close("", app_error(code));
            }
            None => {
                let _ = error.set(SessionError::LocallyClosed);
                let _ = conn.close("", app_error(0));
            }
        }

        let _ = closed_tx.send(true);
    }

    async fn read_capsules(recv: StreamReader) -> Option<(u32, String)> {
        let mut reader = web_transport_proto::Http3CapsuleReader::new(recv);
        loop {
            match reader.read().await {
                Ok(Some(web_transport_proto::Capsule::CloseWebTransportSession {
                    code,
                    reason,
                })) => return Some((code, reason)),
                Ok(Some(web_transport_proto::Capsule::Grease { .. })) => {}
                Ok(Some(web_transport_proto::Capsule::Unknown { typ, payload })) => {
                    tracing::warn!(%typ, size = payload.len(), "unknown capsule");
                }
                Ok(None) => return None,
                Err(e) => {
                    tracing::warn!(?e, "failed to read capsule");
                    return None;
                }
            }
        }
    }

    /// Accept a new unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, SessionError> {
        loop {
            let (_sid, mut recv) = self
                .conn
                .accept_uni_stream()
                .await
                .map_err(|e| self.map_error(e.into()))?;

            let typ = match VarInt::read(&mut recv).await {
                Ok(typ) => StreamUni(typ),
                Err(_) => continue,
            };

            match typ {
                StreamUni::WEBTRANSPORT => {
                    let session_id = VarInt::read(&mut recv)
                        .await
                        .map_err(|_| WebTransportError::UnknownSession)?;
                    if session_id != self.session_id {
                        return Err(WebTransportError::UnknownSession.into());
                    }
                    return Ok(RecvStream::new(recv, self.error.clone()));
                }
                _ => {
                    tracing::debug!(?typ, "ignoring non-webtransport unidirectional stream");
                }
            }
        }
    }

    /// Accept a new bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        loop {
            let (_sid, (mut recv, send)) = self
                .conn
                .accept_bi_stream()
                .await
                .map_err(|e| self.map_error(e.into()))?;

            let typ = match VarInt::read(&mut recv).await {
                Ok(typ) => typ,
                Err(_) => continue,
            };
            if Frame(typ) != Frame::WEBTRANSPORT {
                tracing::debug!(?typ, "ignoring non-webtransport bidirectional stream");
                continue;
            }

            let session_id = VarInt::read(&mut recv)
                .await
                .map_err(|_| WebTransportError::UnknownSession)?;
            if session_id != self.session_id {
                return Err(WebTransportError::UnknownSession.into());
            }

            return Ok((
                SendStream::new(send, self.error.clone()),
                RecvStream::new(recv, self.error.clone()),
            ));
        }
    }

    /// Open a new unidirectional stream.
    pub async fn open_uni(&self) -> Result<SendStream, SessionError> {
        let (_sid, mut send) = self
            .conn
            .open_uni_stream()
            .await
            .map_err(|e| self.map_error(e.into()))?
            .ok_or_else(|| self.closed_error())?;

        send.write_all(&self.header_uni)
            .await
            .map_err(|_| self.closed_error())?;

        Ok(SendStream::new(send, self.error.clone()))
    }

    /// Open a new bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        let (_sid, (recv, mut send)) = self
            .conn
            .open_bi_stream()
            .await
            .map_err(|e| self.map_error(e.into()))?
            .ok_or_else(|| self.closed_error())?;

        send.write_all(&self.header_bi)
            .await
            .map_err(|_| self.closed_error())?;

        Ok((
            SendStream::new(send, self.error.clone()),
            RecvStream::new(recv, self.error.clone()),
        ))
    }

    /// Receive an application datagram from the peer.
    pub async fn read_datagram(&self) -> Result<Bytes, SessionError> {
        let reader = self
            .datagram_reader
            .as_ref()
            .ok_or(SessionError::DatagramUnsupported)?;

        let mut datagram = poll_fn(|cx| reader.poll_recv(cx))
            .await
            .map_err(|_| self.closed_error())?;

        let mut cursor = Cursor::new(&datagram);

        // Strip and validate the session ID prefix.
        let actual_id =
            VarInt::decode(&mut cursor).map_err(|_| WebTransportError::UnknownSession)?;
        if actual_id != self.session_id {
            return Err(WebTransportError::UnknownSession.into());
        }

        let datagram = datagram.split_off(cursor.position() as usize);
        Ok(datagram)
    }

    /// Send an application datagram to the peer.
    ///
    /// Datagrams are unreliable and may be dropped or delivered out of order. The data must be
    /// smaller than [`max_datagram_size`](Self::max_datagram_size).
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SessionError> {
        let writer = self
            .datagram_writer
            .as_ref()
            .ok_or(SessionError::DatagramUnsupported)?;

        let mut buf = BytesMut::with_capacity(self.header_datagram.len() + data.len());
        buf.extend_from_slice(&self.header_datagram);
        buf.extend_from_slice(&data);

        writer
            .send_bytes(buf.freeze())
            .map_err(|_| SendDatagramError::TooLarge.into())
    }

    /// The maximum size of a datagram that can be sent.
    pub fn max_datagram_size(&self) -> usize {
        let max = self
            .datagram_writer
            .as_ref()
            .and_then(|w| w.max_datagram_frame_size().ok())
            .unwrap_or(0);

        // Subtract one byte for the datagram frame type encoding, plus our session ID prefix.
        max.saturating_sub(1)
            .saturating_sub(self.header_datagram.len())
    }

    /// Close the session with an error code and reason.
    ///
    /// A `CloseWebTransportSession` capsule is written on the CONNECT stream before the QUIC
    /// connection is closed, so browser clients can observe the code and reason. This happens
    /// asynchronously; `await` [`closed()`](Self::closed) to ensure delivery.
    pub fn close(&self, code: u32, reason: &[u8]) {
        let reason = String::from_utf8_lossy(reason).into_owned();
        let err = SessionError::WebTransportError(WebTransportError::Closed(code, reason.clone()));
        if self.error.set(err).is_err() {
            // Already closing/closed.
            return;
        }

        let send = self.connect_send.lock().unwrap().take();
        if let Some(send) = send {
            let conn = self.conn.clone();
            let capsule = web_transport_proto::Capsule::CloseWebTransportSession { code, reason };
            tokio::spawn(Self::close_with_capsule(
                conn,
                send,
                capsule,
                code,
                Duration::from_secs(1),
            ));
        } else {
            let _ = self.conn.close("", app_error(code));
        }
    }

    async fn close_with_capsule(
        conn: Connection,
        mut send: StreamWriter,
        capsule: web_transport_proto::Capsule,
        code: u32,
        timeout: Duration,
    ) {
        // Encode the capsule, then wrap it in an HTTP/3 DATA frame (RFC 9297 §3.2).
        let mut capsule_bytes = Vec::new();
        capsule.encode(&mut capsule_bytes);

        let mut frame = Vec::new();
        Frame::DATA.encode(&mut frame);
        let Ok(len) = VarInt::try_from(capsule_bytes.len()) else {
            tracing::warn!("capsule too large to encode as DATA frame");
            let _ = conn.close("", app_error(code));
            return;
        };
        len.encode(&mut frame);
        frame.extend_from_slice(&capsule_bytes);

        let graceful = async {
            let _ = send.write_all(&frame).await;
            // Wait for the peer to acknowledge the capsule before force-closing.
            let _ = send.shutdown().await;
        };

        let _ = tokio::time::timeout(timeout, graceful).await;
        let _ = conn.close("", app_error(code));
    }

    /// Wait until the session is closed, returning the error.
    ///
    /// If the peer sent a `CloseWebTransportSession` capsule, the returned error will be
    /// [`WebTransportError::Closed`] with the code and reason from the capsule.
    pub async fn closed(&self) -> SessionError {
        let mut rx = self.closed_rx.clone();
        let _ = rx.wait_for(|closed| *closed).await;
        self.error
            .get()
            .cloned()
            .unwrap_or(SessionError::LocallyClosed)
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: SessionError) -> SessionError {
        if let Some(err) = self.error.get() {
            if matches!(
                &e,
                SessionError::ConnectionError(_)
                    | SessionError::WebTransportError(WebTransportError::Closed(..))
                    | SessionError::LocallyClosed
            ) {
                return err.clone();
            }
        }
        e
    }

    fn closed_error(&self) -> SessionError {
        self.error
            .get()
            .cloned()
            .unwrap_or(SessionError::LocallyClosed)
    }

    /// Returns the CONNECT request.
    pub fn request(&self) -> &ConnectRequest {
        &self.request
    }

    /// Returns the CONNECT response.
    pub fn response(&self) -> &ConnectResponse {
        &self.response
    }
}

impl web_transport_trait::Session for Session {
    type SendStream = SendStream;
    type RecvStream = RecvStream;
    type Error = SessionError;

    async fn accept_uni(&self) -> Result<Self::RecvStream, Self::Error> {
        Self::accept_uni(self).await
    }

    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::Error> {
        Self::accept_bi(self).await
    }

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::Error> {
        Self::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<Self::SendStream, Self::Error> {
        Self::open_uni(self).await
    }

    fn close(&self, code: u32, reason: &str) {
        Self::close(self, code, reason.as_bytes());
    }

    async fn closed(&self) -> Self::Error {
        Self::closed(self).await
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), Self::Error> {
        Self::send_datagram(self, data)
    }

    async fn recv_datagram(&self) -> Result<Bytes, Self::Error> {
        Self::read_datagram(self).await
    }

    fn max_datagram_size(&self) -> usize {
        Self::max_datagram_size(self)
    }

    fn protocol(&self) -> Option<&str> {
        self.response.protocol.as_deref()
    }
}
