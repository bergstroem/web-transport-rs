//! End-to-end tests: an in-process dquic WebTransport server and client exchanging
//! streams, datagrams, and a graceful close.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;

use dquic::qinterface::component::route::QuicRouter;
use web_transport_dquic::{
    ClientBuilder, RecvStream, ServerBuilder, Session, SessionError, WebTransportError,
};

/// Spin up a server + client on loopback and return both ends of an established session.
///
/// A dedicated [`QuicRouter`] is wired into both the server and the client so that tests can run
/// in parallel without colliding on dquic's process-global router. The client connects by the
/// `localhost` host name so the self-signed `localhost` certificate validates via SNI.
async fn connect() -> (Session, Session, web_transport_dquic::Server) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let router = Arc::new(QuicRouter::default());

    let server = ServerBuilder::new()
        .with_addr("127.0.0.1:0".parse().unwrap())
        .with_server_name("localhost")
        .with_router(router.clone())
        .with_certificate(vec![cert_der.clone()], key_der)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();

    let client = ClientBuilder::new()
        .with_router(router)
        .with_server_certificates(vec![cert_der])
        .unwrap();

    let accept = tokio::spawn(async move {
        let mut server = server;
        let request = server.accept().await.expect("server accept");
        let session = request.ok().await.expect("server respond");
        (session, server)
    });

    let url = Url::parse(&format!("https://localhost:{}/", addr.port())).unwrap();
    let client_session = client.connect(url).await.expect("client connect");

    let (server_session, server) = accept.await.unwrap();
    (client_session, server_session, server)
}

async fn read_all(recv: &mut RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[tokio::test]
async fn bidirectional_echo() {
    let (client, server, _guard) = connect().await;

    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = read_all(&mut recv).await;
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
    });

    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"hello webtransport").await.unwrap();
    send.finish().unwrap();

    let echoed = read_all(&mut recv).await;
    assert_eq!(echoed, b"hello webtransport");

    server_task.await.unwrap();
}

#[tokio::test]
async fn unidirectional() {
    let (client, server, _guard) = connect().await;

    let server_task = tokio::spawn(async move {
        let mut recv = server.accept_uni().await.unwrap();
        read_all(&mut recv).await
    });

    let mut send = client.open_uni().await.unwrap();
    send.write_all(b"one way").await.unwrap();
    send.finish().unwrap();

    let got = server_task.await.unwrap();
    assert_eq!(got, b"one way");
}

// dquic 0.5.x queues outgoing datagram frames but never serializes them into packets
// (`qconnection`'s `path::burst` has `// TODO: datagram`), so this round-trip cannot complete
// upstream yet. The send/recv plumbing here is correct and this test should pass once dquic
// implements outgoing datagram framing. See the crate-level docs.
#[ignore = "dquic 0.5.x does not transmit outgoing datagrams yet"]
#[tokio::test]
async fn datagrams() {
    let (client, server, _guard) = connect().await;

    // Datagrams are unreliable, so keep sending until one arrives.
    let sender = tokio::spawn(async move {
        loop {
            let _ = client.send_datagram(Bytes::from_static(b"datagram"));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let got = tokio::time::timeout(Duration::from_secs(5), server.read_datagram())
        .await
        .expect("datagram timeout")
        .unwrap();
    sender.abort();

    assert_eq!(&got[..], b"datagram");
}

#[tokio::test]
async fn graceful_close() {
    let (client, server, _guard) = connect().await;

    client.close(42, b"goodbye");

    let err = tokio::time::timeout(Duration::from_secs(5), server.closed())
        .await
        .expect("close timeout");

    match err {
        SessionError::WebTransportError(WebTransportError::Closed(code, reason)) => {
            assert_eq!(code, 42);
            assert_eq!(reason, "goodbye");
        }
        other => panic!("unexpected close error: {other:?}"),
    }
}
