//! WebTransport is a protocol for client-server communication over QUIC.
//! It's [available in the browser](https://caniuse.com/webtransport) as an alternative to HTTP and WebSockets.
//!
//! WebTransport is layered on top of HTTP/3 which is then layered on top of QUIC.
//! This crate implements that layering on top of [dquic](https://github.com/genmeta/dquic),
//! exposing an API that mirrors the other `web-transport-*` backends and implements
//! the [`web_transport_trait`] interface.
//!
//! # Limitations
//! Like the other backends in this workspace, this crate does the bare minimum to support a
//! single WebTransport session that owns the entire QUIC connection. It does not support
//! pooling multiple sessions (or HTTP/3) over the same connection.
//!
//! dquic differs from Quinn in a few ways that affect this crate:
//!   - Servers are keyed by SNI (server name); [`ServerBuilder::with_server_name`] selects it.
//!   - Streams expose tokio's `AsyncRead`/`AsyncWrite`; there is no per-stream priority knob, so
//!     [`SendStream::set_priority`] is a no-op.
//!   - `QuicListeners` register on a process-global router; [`ServerBuilder::with_router`] and
//!     [`ClientBuilder::with_router`] allow isolating instances (used by the tests).
//!
//! # Datagrams
//! The datagram API ([`Session::send_datagram`]/[`Session::recv_datagram`]) is fully implemented
//! here, but **outgoing datagrams do not work with dquic 0.5.x**: that release queues datagram
//! frames but never serializes them into packets (see the `// TODO: datagram` markers in
//! `qconnection`'s `path::burst`). Sends therefore appear to succeed but are silently dropped;
//! receiving works once the peer can send. This crate's datagram support will start working as
//! soon as dquic implements outgoing datagram framing, with no changes here.

// External
mod client;
mod error;
mod recv;
mod send;
mod server;
mod session;

pub use client::*;
pub use error::*;
pub use recv::*;
pub use send::*;
pub use server::*;
pub use session::*;

// Internal
mod connect;
mod settings;

use connect::*;
use settings::*;

// Required to access the wrapped proto ConnectError.
pub use connect::ConnectError;

/// The HTTP/3 ALPN is required when negotiating a QUIC connection.
pub const ALPN: &str = "h3";

/// Simple rustls crypto provider utilities.
pub mod crypto;

/// Re-export the underlying QUIC implementation.
pub use dquic;

/// Re-export the http crate because it's in the public API.
pub use http;

/// Re-export the generic WebTransport trait.
pub use web_transport_trait as generic;

/// Re-export the WebTransport protocol implementation.
pub use web_transport_proto as proto;

/// Convert a WebTransport `u32` error code into the reserved HTTP/3 error space used on the wire.
pub(crate) fn app_error(code: u32) -> u64 {
    web_transport_proto::error_to_http3(code)
}

/// The size we advertise for `max_datagram_frame_size` (RFC 9221). This enables QUIC datagrams,
/// which are disabled by default in dquic's handy transport parameters.
pub(crate) const MAX_DATAGRAM_FRAME_SIZE: u64 = 65535;
