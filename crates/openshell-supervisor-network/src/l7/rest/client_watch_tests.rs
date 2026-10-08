// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The client watch on responses relayed without middleware, over TCP, and
//! over TLS.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::task::JoinHandle;

use super::client_link::HALF_CLOSE_IDLE_TIMEOUT;
use super::*;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const SSE_HEAD_AND_FIRST_EVENT: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n";

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .expect("operation finished in time")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn read_until<S: AsyncRead + Unpin>(stream: &mut S, delivered: &mut Vec<u8>, marker: &[u8]) {
    within(async {
        let mut buffer = [0u8; 4096];
        while !contains(delivered, marker) {
            let read = stream.read(&mut buffer).await.expect("read");
            assert!(
                read > 0,
                "closed before {:?}: {:?}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(delivered)
            );
            delivered.extend_from_slice(&buffer[..read]);
        }
    })
    .await;
}

fn gone(error: &miette::Report) -> Option<ClientGone> {
    error
        .downcast_ref::<DownstreamClosed>()
        .map(|closed| closed.gone)
}

/// One response relayed without middleware. The test is the client on
/// `client` and the upstream on `upstream`.
struct Plain {
    upstream: DuplexStream,
    client: DuplexStream,
    task: JoinHandle<Result<RelayOutcome>>,
}

fn plain() -> Plain {
    let (mut relay_upstream, upstream) = tokio::io::duplex(64 * 1024);
    let (relay_client, client) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        relay_response(
            "GET",
            &mut relay_upstream,
            &mut BufReader::new(relay_client),
            RelayResponseOptions::default(),
            None,
        )
        .await
    });
    Plain {
        upstream,
        client,
        task,
    }
}

/// Responses without middleware end when the client closes during upstream
/// silence, whatever their framing, and the upstream connection is released.
#[tokio::test(start_paused = true)]
async fn uninspected_responses_end_when_the_client_closes_during_silence() {
    for (response, marker) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial"[..],
            &b"partial"[..],
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\npartial\r\n",
            b"partial\r\n",
        ),
        // Close-delimited server-sent events have no idle timeout.
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\n",
            b"data: one\n\n",
        ),
    ] {
        let Plain {
            mut upstream,
            mut client,
            task,
        } = plain();
        upstream.write_all(response).await.expect("response start");
        let mut delivered = Vec::new();
        read_until(&mut client, &mut delivered, marker).await;
        tokio::time::sleep(Duration::from_mins(5)).await;
        assert!(!task.is_finished());

        client.shutdown().await.expect("client close");
        let error = within(task)
            .await
            .expect("join relay")
            .expect_err("the client went away");
        assert_eq!(gone(&error), Some(ClientGone::Closed), "{error}");
        let mut unexpected = Vec::new();
        within(upstream.read_to_end(&mut unexpected))
            .await
            .expect("the upstream connection closed");
        assert!(unexpected.is_empty());
    }
}

/// A failed write to the client is a typed client disconnect, like a close
/// the watch saw, even when the watch saw nothing.
#[tokio::test]
async fn a_failed_client_write_is_a_downstream_close() {
    struct BrokenPipe;

    impl AsyncWrite for BrokenPipe {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let (mut relay_upstream, mut upstream) = tokio::io::duplex(64 * 1024);
    upstream
        .write_all(SSE_HEAD_AND_FIRST_EVENT)
        .await
        .expect("response start");
    let error = within(relay_response(
        "GET",
        &mut relay_upstream,
        &mut ReceivingClient(BrokenPipe),
        RelayResponseOptions::default(),
        None,
    ))
    .await
    .expect_err("the client is gone");
    assert_eq!(
        gone(&error),
        Some(ClientGone::Failed(std::io::ErrorKind::BrokenPipe)),
        "{error}"
    );
}

/// An interim response is not the final head: a client that closes after a
/// `103 Early Hints` is treated as half-closed.
#[tokio::test(start_paused = true)]
async fn a_close_after_an_interim_response_is_a_half_close() {
    let Plain {
        mut upstream,
        mut client,
        task,
    } = plain();
    upstream
        .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload\r\n\r\n")
        .await
        .expect("interim response");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"\r\n\r\n").await;
    client.shutdown().await.expect("client close");

    tokio::time::sleep(HALF_CLOSE_IDLE_TIMEOUT.saturating_sub(Duration::from_secs(1))).await;
    assert!(!task.is_finished());
    tokio::time::sleep(Duration::from_secs(2)).await;
    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("the idle half-closed response ends");
    assert_eq!(gone(&error), Some(ClientGone::HalfCloseIdle), "{error}");
}

/// A close that arrives together with the upstream head is judged by
/// whether it was readable when the head was written: it is a half-close,
/// and the response is still delivered.
#[tokio::test(start_paused = true)]
async fn a_close_ready_before_the_head_is_written_is_a_half_close() {
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(64 * 1024);
    let (relay_client, mut client) = tokio::io::duplex(64 * 1024);
    upstream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")
        .await
        .expect("head and part of the body");
    client.shutdown().await.expect("half-close");
    let task = tokio::spawn(async move {
        relay_response(
            "GET",
            &mut relay_upstream,
            &mut BufReader::new(relay_client),
            RelayResponseOptions::default(),
            None,
        )
        .await
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    upstream
        .write_all(b"world")
        .await
        .expect("rest of the body");

    let mut delivered = Vec::new();
    within(client.read_to_end(&mut delivered))
        .await
        .expect("the connection closes after the response");
    assert_eq!(
        delivered,
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhelloworld"
    );
    let outcome = within(task).await.expect("join relay");
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
}

/// Scripted clients such as `nc -N` send the request and close their sending
/// side at once. They still get a response that arrives within the idle
/// limit, and the connection then closes instead of waiting for another
/// request.
#[tokio::test(start_paused = true)]
async fn a_request_followed_by_a_half_close_still_gets_its_response() {
    let req = L7Request {
        action: "POST".into(),
        target: "/v1/items".into(),
        query_params: HashMap::new(),
        raw_header:
            b"POST /v1/items HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\n\r\n"
                .to_vec(),
        body_length: BodyLength::ContentLength(5),
    };
    let (mut app, relay_client) = tokio::io::duplex(64 * 1024);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(64 * 1024);
    app.write_all(b"hello").await.expect("body");
    app.shutdown().await.expect("half-close");
    let task = tokio::spawn(async move {
        relay_http_request_with_options_guarded(
            &req,
            &mut BufReader::new(relay_client),
            &mut relay_upstream,
            RelayRequestOptions::default(),
        )
        .await
    });
    let mut forwarded = Vec::new();
    read_until(&mut upstream, &mut forwarded, b"\r\n\r\nhello").await;
    tokio::time::sleep(Duration::from_secs(20)).await;
    upstream
        .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
        .await
        .expect("response");

    let mut response = Vec::new();
    within(app.read_to_end(&mut response))
        .await
        .expect("the connection closes after the response");
    assert_eq!(
        response,
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"
    );
    let outcome = within(task).await.expect("join relay");
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
}

/// A real TCP reset ends the response at once.
#[tokio::test]
async fn a_tcp_reset_ends_the_response_at_once() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let peer = tokio::net::TcpStream::connect(listener.local_addr().expect("address"))
        .await
        .expect("connect");
    let (accepted, _) = listener.accept().await.expect("accept");
    openshell_core::net::set_tcp_nodelay_best_effort(&peer);
    openshell_core::net::set_tcp_nodelay_best_effort(&accepted);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        relay_response(
            "GET",
            &mut relay_upstream,
            &mut BufReader::new(accepted),
            RelayResponseOptions::default(),
            None,
        )
        .await
    });
    upstream
        .write_all(SSE_HEAD_AND_FIRST_EVENT)
        .await
        .expect("first event");
    let mut peer = peer;
    let mut delivered = Vec::new();
    read_until(&mut peer, &mut delivered, b"data: one\n\n").await;
    peer.set_zero_linger().expect("SO_LINGER 0");
    drop(peer);

    let error = within(task)
        .await
        .expect("join relay")
        .expect_err("the client went away");
    assert_eq!(
        gone(&error),
        Some(ClientGone::Failed(std::io::ErrorKind::ConnectionReset)),
        "{error}"
    );
}

/// TLS client configuration that trusts a fresh sandbox CA.
fn tls_configs() -> (crate::l7::tls::SandboxCa, Arc<rustls::ClientConfig>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = crate::l7::tls::SandboxCa::generate().expect("sandbox CA");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
        roots.add(cert.expect("CA certificate")).expect("trust CA");
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    (ca, config)
}

type TlsClient = tokio_rustls::client::TlsStream<DuplexStream>;

/// Relay one response to a TLS client the relay terminates. After the
/// response, the relay task reads what the client sent next.
async fn tls_relay() -> (
    TlsClient,
    DuplexStream,
    JoinHandle<(Result<RelayOutcome>, Vec<u8>)>,
) {
    let (ca, config) = tls_configs();
    let (caller, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut relay_upstream, upstream) = tokio::io::duplex(64 * 1024);
    let server_config = Arc::clone(&config);
    let task = tokio::spawn(async move {
        let state =
            crate::l7::tls::ProxyTlsState::new(crate::l7::tls::CertCache::new(ca), server_config);
        let mut client = crate::l7::tls::tls_terminate_client(relay_side, &state, "example.com")
            .await
            .expect("TLS handshake");
        let outcome = relay_response(
            "GET",
            &mut relay_upstream,
            &mut client,
            RelayResponseOptions::default(),
            None,
        )
        .await;
        let mut next = Vec::new();
        if matches!(outcome, Ok(RelayOutcome::Reusable)) {
            let mut buffer = [0u8; 256];
            let read = client.read(&mut buffer).await.expect("next request");
            next.extend_from_slice(&buffer[..read]);
        }
        (outcome, next)
    });
    let client = tokio_rustls::TlsConnector::from(config)
        .connect(
            rustls::pki_types::ServerName::try_from("example.com").expect("server name"),
            caller,
        )
        .await
        .expect("TLS handshake");
    (client, upstream, task)
}

/// Under TLS the watch reads through the TLS layer: `close_notify` without a
/// TCP close, and a TCP close without `close_notify`, each end a response
/// whose head reached the client.
#[tokio::test]
async fn a_tls_close_notify_or_bare_fin_ends_the_response() {
    for close_notify in [true, false] {
        let (mut client, mut upstream, task) = tls_relay().await;
        upstream
            .write_all(SSE_HEAD_AND_FIRST_EVENT)
            .await
            .expect("first event");
        let mut delivered = Vec::new();
        read_until(&mut client, &mut delivered, b"data: one\n\n").await;
        if close_notify {
            client.get_mut().1.send_close_notify();
            client.flush().await.expect("close_notify");
        } else {
            client.get_mut().0.shutdown().await.expect("TCP close");
        }

        let (outcome, _) = within(task).await.expect("join relay");
        let error = outcome.expect_err("the client went away");
        assert_eq!(
            gone(&error),
            Some(ClientGone::Closed),
            "close_notify={close_notify}: {error}"
        );
    }
}

/// An encrypted pipelined request stops the watch, and its plaintext stays
/// buffered for the next request.
#[tokio::test(start_paused = true)]
async fn an_encrypted_pipelined_request_stays_buffered() {
    let (mut client, mut upstream, task) = tls_relay().await;
    upstream
        .write_all(SSE_HEAD_AND_FIRST_EVENT)
        .await
        .expect("first event");
    let mut delivered = Vec::new();
    read_until(&mut client, &mut delivered, b"data: one\n\n").await;
    client
        .write_all(b"GET /next HTTP/1.1\r\n\r\n")
        .await
        .expect("next request");
    client.flush().await.expect("flush");

    tokio::time::sleep(Duration::from_mins(5)).await;
    assert!(!task.is_finished());
    upstream.write_all(b"0\r\n\r\n").await.expect("last chunk");
    let (outcome, next) = within(task).await.expect("join relay");
    assert!(matches!(outcome, Ok(RelayOutcome::Reusable)), "{outcome:?}");
    assert_eq!(next, b"GET /next HTTP/1.1\r\n\r\n");
}

/// TLS 1.3 allows a half-close: a client that sends `close_notify` before
/// the head still receives the response, and the relay closes the session
/// with its own `close_notify` afterwards.
#[tokio::test(start_paused = true)]
async fn a_tls_half_close_before_the_head_still_gets_the_response() {
    let (mut client, mut upstream, task) = tls_relay().await;
    client.get_mut().1.send_close_notify();
    client.flush().await.expect("close_notify");
    tokio::time::sleep(Duration::from_secs(1)).await;
    upstream
        .write_all(SSE_HEAD_AND_FIRST_EVENT)
        .await
        .expect("first event");
    upstream.write_all(b"0\r\n\r\n").await.expect("last chunk");

    let mut delivered = Vec::new();
    within(client.read_to_end(&mut delivered))
        .await
        .expect("the response ends with close_notify");
    assert!(delivered.ends_with(b"data: one\n\n\r\n0\r\n\r\n"));
    let (outcome, _) = within(task).await.expect("join relay");
    assert!(matches!(outcome, Ok(RelayOutcome::Consumed)), "{outcome:?}");
}
