use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use dquic::prelude::{BindUri, Connection, ParameterId, QuicListeners};
use dquic::qbase::net::addr::BoundAddr;
use dquic::qbase::param::ServerParameters;
use dquic::qinterface::component::route::QuicRouter;
use dquic::qinterface::io::IO;

use crate::{
    proto::{ConnectRequest, ConnectResponse},
    Connecting, ServerError, Session, Settings, ALPN, MAX_DATAGRAM_FRAME_SIZE,
};

/// The maximum number of pending connections queued by the listener.
const BACKLOG: usize = 1024;

/// Build the server transport parameters, enabling QUIC datagrams (disabled by default).
fn server_parameters() -> ServerParameters {
    let mut params = dquic::prelude::handy::server_parameters();
    params
        .set(
            ParameterId::MaxDatagramFrameSize,
            MAX_DATAGRAM_FRAME_SIZE as u32,
        )
        .expect("max_datagram_frame_size is a valid server parameter");
    params
}

/// Construct a WebTransport [`Server`] using sane defaults.
pub struct ServerBuilder {
    provider: crate::crypto::Provider,
    addr: SocketAddr,
    server_name: String,
    router: Option<Arc<QuicRouter>>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBuilder {
    /// Create a server builder with sane defaults.
    pub fn new() -> Self {
        Self {
            provider: crate::crypto::default_provider(),
            addr: "[::]:443".parse().unwrap(),
            server_name: "localhost".to_string(),
            router: None,
        }
    }

    /// Listen on the specified address.
    pub fn with_addr(self, addr: SocketAddr) -> Self {
        Self { addr, ..self }
    }

    /// Set the server name (SNI) that this server answers for.
    ///
    /// dquic routes incoming connections to a server by the SNI in the client's `ClientHello`,
    /// so the client must connect using a matching host name. Defaults to `"localhost"`.
    pub fn with_server_name(self, server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            ..self
        }
    }

    /// Use a specific QUIC router instead of the process-global one.
    ///
    /// This is primarily useful for tests that need to isolate multiple endpoints in one process.
    pub fn with_router(mut self, router: Arc<QuicRouter>) -> Self {
        self.router = Some(router);
        self
    }

    /// Supply a certificate chain and private key used for TLS.
    pub async fn with_certificate(
        self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Server, ServerError> {
        let builder = QuicListeners::builder_with_crypto_provider(self.provider.clone())?;
        let builder = match self.router {
            Some(router) => builder.with_router(router),
            None => builder,
        };
        let listeners = builder
            .without_client_cert_verifier()
            .with_alpns([ALPN.as_bytes().to_vec()])
            .with_parameters(server_parameters())
            .listen(BACKLOG)
            .map_err(|e| ServerError::Build(e.to_string()))?;

        let bind_uri = Self::bind_uri(self.addr);
        listeners
            .add_server(self.server_name.clone(), chain, key, [bind_uri], None)
            .await
            .map_err(|e| ServerError::Build(e.to_string()))?;

        let local_addr = Self::discover_addr(&listeners, &self.server_name)?;

        Ok(Server {
            listeners,
            server_name: self.server_name,
            local_addr,
        })
    }

    fn bind_uri(addr: SocketAddr) -> BindUri {
        let uri = BindUri::from_str(&format!("inet://{addr}")).expect("valid bind uri");
        if addr.port() == 0 {
            uri.alloc_port()
        } else {
            uri
        }
    }

    fn discover_addr(
        listeners: &QuicListeners,
        server_name: &str,
    ) -> Result<SocketAddr, ServerError> {
        let server = listeners
            .get_server(server_name)
            .ok_or_else(|| ServerError::Build("server not registered".to_string()))?;
        let ifaces = server.bind_interfaces();
        let iface = ifaces
            .into_values()
            .next()
            .ok_or_else(|| ServerError::Build("no bound interface".to_string()))?;
        let bound = iface
            .borrow()
            .bound_addr()
            .map_err(|e| ServerError::Build(e.to_string()))?;
        match bound {
            BoundAddr::Internet(addr) => Ok(addr),
            _ => Err(ServerError::Build("non-internet bound address".to_string())),
        }
    }
}

/// A WebTransport server that accepts new sessions.
pub struct Server {
    listeners: Arc<QuicListeners>,
    server_name: String,
    local_addr: SocketAddr,
}

impl Server {
    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Returns the server name (SNI) this server answers for.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Accept a new WebTransport session [`Request`] from a client.
    pub async fn accept(&mut self) -> Option<Request> {
        loop {
            let (conn, _server_name, _pathway, _link) = self.listeners.accept().await.ok()?;
            match Request::accept(conn).await {
                Ok(request) => return Some(request),
                Err(err) => {
                    tracing::debug!(?err, "failed to accept WebTransport request");
                    continue;
                }
            }
        }
    }
}

/// A mostly complete WebTransport handshake, awaiting the server's accept/reject decision.
pub struct Request {
    conn: Connection,
    settings: Settings,
    connect: Connecting,
}

impl Request {
    /// Perform the handshake on a freshly accepted QUIC connection.
    pub async fn accept(conn: Connection) -> Result<Self, ServerError> {
        // Perform the H3 handshake by sending/receiving SETTINGS frames.
        let settings = Settings::connect(&conn).await?;

        // Accept the CONNECT request but don't respond yet.
        let connect = Connecting::accept(&conn).await?;

        Ok(Self {
            conn,
            settings,
            connect,
        })
    }

    /// Accept the session with a 200 OK response.
    pub async fn ok(self) -> Result<Session, ServerError> {
        self.respond(ConnectResponse::OK).await
    }

    /// Reply to the session with the given response, usually 200 OK.
    ///
    /// [`ConnectResponse::with_protocol`] can be used to select a subprotocol.
    pub async fn respond(
        self,
        response: impl Into<ConnectResponse>,
    ) -> Result<Session, ServerError> {
        let response = response.into();
        let connect = self.connect.respond(response).await?;
        let (datagram_reader, datagram_writer) = Session::datagrams(&self.conn).await;
        Ok(Session::new(
            self.conn,
            self.settings,
            connect,
            datagram_reader,
            datagram_writer,
        ))
    }

    /// Reject the session with the given status code.
    pub async fn reject(self, status: http::StatusCode) -> Result<(), ServerError> {
        self.connect.reject(status).await?;
        Ok(())
    }

    /// Returns the CONNECT request that was sent by the client.
    pub fn connect(&self) -> &ConnectRequest {
        &self.connect.request
    }
}

impl core::ops::Deref for Request {
    type Target = ConnectRequest;

    fn deref(&self) -> &Self::Target {
        &self.connect.request
    }
}
