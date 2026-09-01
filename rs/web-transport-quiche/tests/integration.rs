//! End-to-end tests: an in-process quiche WebTransport server and client exchanging
//! bidirectional and unidirectional streams in both directions.

use std::time::Duration;

use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;
use web_transport_quiche::{ClientBuilder, Connection, RecvStream, ServerBuilder, Settings};

/// How long a stream is expected to take; also how long the peer that isn't under test
/// is kept alive, since dropping a [`Connection`] closes the whole QUIC connection.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Spin up a server + client on loopback and return both ends of an established session.
/// The [`web_transport_quiche::Server`] is returned so the caller keeps the endpoint alive.
async fn connect_with(
    tweak: impl FnOnce(&mut Settings),
) -> (Connection, Connection, web_transport_quiche::Server) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut settings = Settings::default();
    tweak(&mut settings);

    // The self-signed cert isn't in the system roots, so skip verification.
    let mut client_settings = settings.clone();
    client_settings.verify_peer = false;

    let server = ServerBuilder::default()
        .with_bind("127.0.0.1:0")
        .unwrap()
        .with_settings(settings)
        .with_single_cert(chain, key)
        .unwrap();

    let addr = server.local_addrs()[0];

    let accept = tokio::spawn(async move {
        let mut server = server;
        let request = server.accept().await.expect("server accept");
        let session = request.ok().await.expect("server respond");
        (session, server)
    });

    let url = Url::parse(&format!("https://localhost:{}/", addr.port())).unwrap();
    let client_session = ClientBuilder::default()
        .with_settings(client_settings)
        .connect(url)
        .await
        .expect("client connect")
        .established()
        .await
        .expect("client established");

    let (server_session, server) = accept.await.unwrap();
    (client_session, server_session, server)
}

async fn connect() -> (Connection, Connection, web_transport_quiche::Server) {
    connect_with(|_| {}).await
}

/// Hold a session open in the background: dropping the last [`Connection`] handle closes
/// the QUIC connection, which would abort the peer mid-test.
fn keepalive(conn: Connection) {
    tokio::spawn(async move {
        tokio::time::sleep(TIMEOUT).await;
        drop(conn);
    });
}

async fn read_all(recv: &mut RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        if n == 0 {
            break;
        }
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
        tokio::time::sleep(TIMEOUT).await;
    });

    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"hello webtransport").await.unwrap();
    send.finish().unwrap();

    let echoed = tokio::time::timeout(TIMEOUT, read_all(&mut recv))
        .await
        .expect("timed out reading bi stream");
    assert_eq!(echoed, b"hello webtransport");

    server_task.abort();
}

#[tokio::test]
async fn uni_client_to_server() {
    let (client, server, _guard) = connect().await;

    let server_task = tokio::spawn(async move {
        let mut recv = server.accept_uni().await.unwrap();
        let data = read_all(&mut recv).await;
        keepalive(server);
        data
    });

    let mut send = client.open_uni().await.unwrap();
    send.write_all(b"client to server").await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(TIMEOUT, server_task)
        .await
        .expect("timed out accepting/reading uni stream")
        .unwrap();
    assert_eq!(data, b"client to server");
}

#[tokio::test]
async fn uni_server_to_client() {
    let (client, server, _guard) = connect().await;

    let client_task = tokio::spawn(async move {
        let mut recv = client.accept_uni().await.unwrap();
        let data = read_all(&mut recv).await;
        keepalive(client);
        data
    });

    let mut send = server.open_uni().await.unwrap();
    send.write_all(b"server to client").await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(TIMEOUT, client_task)
        .await
        .expect("timed out accepting/reading uni stream")
        .unwrap();
    assert_eq!(data, b"server to client");
}

/// Dropping a [`web_transport_quiche::SendStream`] must close it with a FIN, not a
/// RESET_STREAM: a reset discards the WebTransport header that `open_uni` queued, so the
/// peer can't attribute the stream to the session and `accept_uni` hangs forever.
#[tokio::test]
async fn uni_dropped_without_finish_server_to_client() {
    let (client, server, _guard) = connect().await;

    let writer = tokio::spawn(async move {
        let mut send = server.open_uni().await.unwrap();
        send.write_all(b"data plane").await.unwrap();
        // No finish(): just drop, which is how the other backends close a stream.
        drop(send);
        tokio::time::sleep(TIMEOUT).await;
        drop(server);
    });

    let mut recv = tokio::time::timeout(TIMEOUT, client.accept_uni())
        .await
        .expect("accept_uni never resolved for a dropped-without-finish uni stream")
        .unwrap();
    let data = tokio::time::timeout(TIMEOUT, read_all(&mut recv))
        .await
        .expect("timed out reading uni stream");
    assert_eq!(data, b"data plane");

    writer.abort();
}

/// The mirror of [`uni_dropped_without_finish_server_to_client`].
#[tokio::test]
async fn uni_dropped_without_finish_client_to_server() {
    let (client, server, _guard) = connect().await;

    let writer = tokio::spawn(async move {
        let mut send = client.open_uni().await.unwrap();
        send.write_all(b"data plane").await.unwrap();
        drop(send);
        tokio::time::sleep(TIMEOUT).await;
        drop(client);
    });

    let mut recv = tokio::time::timeout(TIMEOUT, server.accept_uni())
        .await
        .expect("accept_uni never resolved for a dropped-without-finish uni stream")
        .unwrap();
    let data = tokio::time::timeout(TIMEOUT, read_all(&mut recv))
        .await
        .expect("timed out reading uni stream");
    assert_eq!(data, b"data plane");

    writer.abort();
}

/// A uni stream opened after a bi-stream round trip, like an application that runs a
/// handshake over a control stream before sending data.
#[tokio::test]
async fn uni_server_to_client_after_bi() {
    let (client, server, _guard) = connect().await;

    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = read_all(&mut recv).await;
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();

        let mut uni = server.open_uni().await.unwrap();
        uni.write_all(b"after bi").await.unwrap();
        uni.finish().unwrap();

        tokio::time::sleep(TIMEOUT).await;
    });

    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let echoed = tokio::time::timeout(TIMEOUT, read_all(&mut recv))
        .await
        .expect("timed out reading bi stream");
    assert_eq!(echoed, b"ping");

    let mut uni = tokio::time::timeout(TIMEOUT, client.accept_uni())
        .await
        .expect("timed out accepting uni stream")
        .unwrap();
    let data = tokio::time::timeout(TIMEOUT, read_all(&mut uni))
        .await
        .expect("timed out reading uni stream");
    assert_eq!(data, b"after bi");

    server_task.abort();
}

/// The server opens the uni stream immediately, racing the client's session setup.
#[tokio::test]
async fn uni_immediately_after_respond() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let server = ServerBuilder::default()
        .with_bind("127.0.0.1:0")
        .unwrap()
        .with_single_cert(chain, key)
        .unwrap();
    let addr = server.local_addrs()[0];

    let accept = tokio::spawn(async move {
        let mut server = server;
        let request = server.accept().await.expect("server accept");
        let session = request.ok().await.expect("server respond");
        let mut send = session.open_uni().await.unwrap();
        send.write_all(b"eager").await.unwrap();
        send.finish().unwrap();
        (session, server)
    });

    let mut settings = Settings::default();
    settings.verify_peer = false;
    let url = Url::parse(&format!("https://localhost:{}/", addr.port())).unwrap();
    let client = ClientBuilder::default()
        .with_settings(settings)
        .connect(url)
        .await
        .unwrap()
        .established()
        .await
        .unwrap();

    let mut recv = tokio::time::timeout(TIMEOUT, client.accept_uni())
        .await
        .expect("timed out accepting eager uni stream")
        .unwrap();
    assert_eq!(read_all(&mut recv).await, b"eager");

    let _guard = accept.await.unwrap();
}

/// Many uni streams back to back, to catch a demux that only works for the first one.
#[tokio::test]
async fn many_uni_streams() {
    let (client, server, _guard) = connect().await;

    const COUNT: usize = 50;

    let reader = tokio::spawn(async move {
        let mut seen = Vec::new();
        for _ in 0..COUNT {
            let mut recv = client.accept_uni().await.unwrap();
            seen.push(read_all(&mut recv).await);
        }
        keepalive(client);
        seen
    });

    for i in 0..COUNT {
        let mut send = server.open_uni().await.unwrap();
        send.write_all(format!("msg-{i}").as_bytes()).await.unwrap();
        send.finish().unwrap();
    }

    let seen = tokio::time::timeout(TIMEOUT, reader)
        .await
        .expect("timed out reading many uni streams")
        .unwrap();
    assert_eq!(seen.len(), COUNT);
}

/// bi and uni traffic in both directions on the same session, with the flow control and
/// congestion control settings a media relay would use.
#[tokio::test]
async fn interleaved_bi_and_uni() {
    let (client, server, _guard) = connect_with(|s| {
        s.initial_max_data = 8 * 1024 * 1024;
        s.initial_max_stream_data_bidi_local = 2 * 1024 * 1024;
        s.initial_max_stream_data_bidi_remote = 2 * 1024 * 1024;
        s.initial_max_stream_data_uni = 2 * 1024 * 1024;
        s.cc_algorithm = "bbr2".to_string();
    })
    .await;

    let echo = server.clone();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = echo.accept_bi().await {
            let data = read_all(&mut recv).await;
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
        }
    });

    let drain = server.clone();
    let drain_task = tokio::spawn(async move {
        while let Ok(mut recv) = drain.accept_uni().await {
            let _ = read_all(&mut recv).await;
        }
    });

    for round in 0..5 {
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(format!("round-{round}").as_bytes())
            .await
            .unwrap();
        send.finish().unwrap();
        let echoed = tokio::time::timeout(TIMEOUT, read_all(&mut recv))
            .await
            .expect("timed out on bi echo");
        assert_eq!(echoed, format!("round-{round}").as_bytes());

        let mut up = client.open_uni().await.unwrap();
        up.write_all(b"up").await.unwrap();
        up.finish().unwrap();

        let mut down = server.open_uni().await.unwrap();
        down.write_all(format!("down-{round}").as_bytes())
            .await
            .unwrap();
        down.finish().unwrap();

        let mut got = tokio::time::timeout(TIMEOUT, client.accept_uni())
            .await
            .expect("timed out accepting server uni stream")
            .unwrap();
        let data = tokio::time::timeout(TIMEOUT, read_all(&mut got))
            .await
            .expect("timed out reading server uni stream");
        assert_eq!(data, format!("down-{round}").as_bytes());
    }

    echo_task.abort();
    drain_task.abort();
}

/// A megabyte over one uni stream, so the flow-controlled path is covered too.
#[tokio::test]
async fn large_uni_stream() {
    let (client, server, _guard) = connect_with(|s| {
        s.initial_max_data = 8 * 1024 * 1024;
        s.initial_max_stream_data_uni = 2 * 1024 * 1024;
    })
    .await;

    const SIZE: usize = 1024 * 1024;

    let writer = tokio::spawn(async move {
        let mut send = server.open_uni().await.unwrap();
        send.write_all(&vec![0xAB; SIZE]).await.unwrap();
        send.finish().unwrap();
        tokio::time::sleep(TIMEOUT).await;
    });

    let mut recv = tokio::time::timeout(TIMEOUT, client.accept_uni())
        .await
        .expect("timed out accepting large uni stream")
        .unwrap();
    let got = tokio::time::timeout(TIMEOUT, read_all(&mut recv))
        .await
        .expect("timed out reading large uni stream");
    assert_eq!(got.len(), SIZE);

    writer.abort();
}

/// A known gap, not a regression: RESET_STREAM discards data QUIC hasn't put on the wire
/// yet, including the WebTransport header `open_uni` queues, so a reset this early makes
/// the stream invisible to the peer instead of surfacing an error. `web-transport-quinn`
/// has the same limitation (see its `open_uni`: "the header is very important for
/// determining the session ID without reliable reset").
#[tokio::test]
#[ignore = "a reset before the WebTransport header is flushed hides the stream from the peer"]
async fn uni_reset_right_after_open_is_visible_to_peer() {
    let (client, server, _guard) = connect().await;

    let writer = tokio::spawn(async move {
        let mut send = server.open_uni().await.unwrap();
        send.write_all(b"doomed").await.unwrap();
        send.reset(7);
        tokio::time::sleep(TIMEOUT).await;
        drop(server);
    });

    let mut recv = tokio::time::timeout(TIMEOUT, client.accept_uni())
        .await
        .expect("accept_uni never resolved for a reset uni stream")
        .unwrap();
    recv.read(&mut [0u8; 16])
        .await
        .expect_err("expected the reset to surface as an error");

    writer.abort();
}
