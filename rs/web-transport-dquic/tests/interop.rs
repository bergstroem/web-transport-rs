//! Cross-stack interop tests between the dquic and quinn backends.
//!
//! All backends in this workspace drive the same `web-transport-proto` for the HTTP/3 SETTINGS
//! exchange, the CONNECT handshake, and the per-stream WebTransport headers, so the bytes on the
//! wire are identical regardless of which QUIC implementation carries them. QUIC v1 + TLS 1.3 is
//! itself interoperable, so a dquic endpoint and a quinn endpoint can talk to each other.
//!
//! Streams are exercised here. Datagrams are intentionally not: dquic 0.5.x does not transmit
//! outgoing datagram frames yet (see the crate-level docs), so a datagram round-trip cannot
//! complete in either direction that involves a dquic sender.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;

use dquic::qinterface::component::route::QuicRouter;
use web_transport_dquic::generic::{RecvStream, SendStream, Session};

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    (cert_der, key)
}

async fn read_all<R: RecvStream>(recv: &mut R) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// Open a bidirectional stream on the client, echo it on the server, and assert the round-trip.
async fn bi_echo<C: Session, S: Session>(client: C, server: S) {
    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = read_all(&mut recv).await;
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
        // Hold the session open until the client has read the echo.
        server
    });

    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"interop hello").await.unwrap();
    send.finish().unwrap();

    let echoed = read_all(&mut recv).await;
    assert_eq!(echoed, b"interop hello");

    let _server = server_task.await.unwrap();
}

#[tokio::test]
async fn dquic_client_to_quinn_server() {
    let (cert, key) = self_signed();

    let mut server = web_transport_quinn::ServerBuilder::new()
        .with_addr("127.0.0.1:0".parse().unwrap())
        .with_certificate(vec![cert.clone()], key)
        .unwrap();
    let addr = server.local_addr().unwrap();

    let client = web_transport_dquic::ClientBuilder::new()
        .with_router(Arc::new(QuicRouter::default()))
        .with_server_certificates(vec![cert])
        .unwrap();

    let accept = tokio::spawn(async move {
        let request = server.accept().await.expect("quinn accept");
        let session = request.ok().await.expect("quinn respond");
        (session, server)
    });

    let url = Url::parse(&format!("https://localhost:{}/", addr.port())).unwrap();
    let client_session = client.connect(url).await.expect("dquic connect");

    let (server_session, _server) = accept.await.unwrap();
    bi_echo(client_session, server_session).await;
}

#[tokio::test]
async fn quinn_client_to_dquic_server() {
    let (cert, key) = self_signed();

    // quinn connects to the first address `localhost` resolves to, so bind the dquic server to
    // that same address family to guarantee the client reaches it.
    let first = tokio::net::lookup_host(("localhost", 0))
        .await
        .unwrap()
        .next()
        .expect("localhost resolves");
    let bind = SocketAddr::new(first.ip(), 0);

    let mut server = web_transport_dquic::ServerBuilder::new()
        .with_addr(bind)
        .with_server_name("localhost")
        .with_router(Arc::new(QuicRouter::default()))
        .with_certificate(vec![cert.clone()], key)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();

    let client = web_transport_quinn::ClientBuilder::new()
        .with_server_certificates(vec![cert])
        .unwrap();

    let accept = tokio::spawn(async move {
        let request = server.accept().await.expect("dquic accept");
        let session = request.ok().await.expect("dquic respond");
        (session, server)
    });

    let url = Url::parse(&format!("https://localhost:{}/", addr.port())).unwrap();
    let client_session = client.connect(url).await.expect("quinn connect");

    let (server_session, _server) = accept.await.unwrap();
    bi_echo(client_session, server_session).await;
}
