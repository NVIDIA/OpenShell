// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::super::{
    BoundaryDuplexStream, RELAY_REVERSE_DRAIN, TcpOpenDecision, complete_network_open,
    read_stream_frame,
};
use crate::boundary_protocol::STREAM_NETWORK_DECISION;

const DUPLEX_CAPACITY: usize = 64 * 1024;
const UPLOAD_LEN: usize = 256 * 1024;
const REJECTION: &[u8] = b"\
HTTP/1.1 403 Forbidden\r\n\
Content-Type: application/json\r\n\
Content-Length: 21\r\n\
Connection: close\r\n\
\r\n\
{\"error\":\"rejected\"}\n";

async fn open_relay() -> (
    tokio::task::JoinHandle<()>,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
) {
    open_relay_with_boundary(|boundary| Box::new(boundary)).await
}

async fn open_relay_with_boundary(
    wrap: impl FnOnce(tokio::io::DuplexStream) -> BoundaryDuplexStream,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
) {
    let (boundary, mut sandbox) = tokio::io::duplex(DUPLEX_CAPACITY);
    let boundary = wrap(boundary);
    let (proxy, transport) = tokio::io::duplex(DUPLEX_CAPACITY);
    let (decision_tx, decision_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(complete_network_open(boundary, transport, decision_rx));
    decision_tx
        .send(TcpOpenDecision::RelayReady)
        .expect("relay task still waiting for the decision");
    let (channel, _) = read_stream_frame(&mut sandbox)
        .await
        .expect("decision frame")
        .expect("decision frame");
    assert_eq!(channel, STREAM_NETWORK_DECISION);
    (task, sandbox, proxy)
}

/// Response writes fail on demand. Upload reads keep working, which is the
/// shape of a proxy that can no longer deliver bytes to the sandbox.
struct ResponseFailure {
    inner: tokio::io::DuplexStream,
    fail: Arc<AtomicBool>,
}

impl AsyncRead for ResponseFailure {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ResponseFailure {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.fail.load(Ordering::Acquire) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "response direction failed",
            )));
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn spawn_upload(
    mut sandbox_write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<usize>) {
    let sent = Arc::new(AtomicUsize::new(0));
    let progress = Arc::clone(&sent);
    let writer = tokio::spawn(async move {
        let body = vec![b'x'; UPLOAD_LEN];
        let mut offset = 0usize;
        while offset < body.len() {
            match sandbox_write.write(&body[offset..]).await {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    offset += count;
                    progress.store(offset, Ordering::Release);
                }
            }
        }
        offset
    });
    (sent, writer)
}

async fn wait_for_upload_progress(sent: &AtomicUsize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while sent.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upload should accept bytes");
}

#[tokio::test]
async fn network_relay_delivers_queued_rejection_after_upload_failure() {
    let (task, sandbox, mut proxy) = open_relay().await;
    let (mut sandbox_read, sandbox_write) = tokio::io::split(sandbox);
    let (sent, writer) = spawn_upload(sandbox_write);
    wait_for_upload_progress(&sent).await;
    assert!(
        !writer.is_finished(),
        "upload writer finished before the proxy rejected it"
    );

    // The L7 relay writes the rejection and then drops its end of the duplex.
    // `split` does not close one direction, so the whole proxy end has to go.
    proxy.write_all(REJECTION).await.expect("queue rejection");
    proxy.flush().await.expect("flush rejection");
    drop(proxy);

    let mut response = vec![0; REJECTION.len()];
    tokio::time::timeout(
        Duration::from_secs(2),
        sandbox_read.read_exact(&mut response),
    )
    .await
    .expect("queued rejection should reach the sandbox")
    .expect("queued rejection");
    assert_eq!(response, REJECTION);

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("relay should finish after the reverse drain")
        .expect("relay task");
    let written = writer.await.expect("upload writer");
    assert!(
        written < UPLOAD_LEN,
        "relay drained the unread upload ({written} bytes)"
    );
}

#[tokio::test]
async fn network_relay_copies_both_directions() {
    let (task, sandbox, proxy) = open_relay().await;
    let (mut sandbox_read, mut sandbox_write) = tokio::io::split(sandbox);
    let (mut proxy_read, mut proxy_write) = tokio::io::split(proxy);

    sandbox_write.write_all(b"ping").await.unwrap();
    proxy_write.write_all(b"pong").await.unwrap();

    let mut from_sandbox = [0; 4];
    proxy_read.read_exact(&mut from_sandbox).await.unwrap();
    let mut from_proxy = [0; 4];
    sandbox_read.read_exact(&mut from_proxy).await.unwrap();
    assert_eq!(&from_sandbox, b"ping");
    assert_eq!(&from_proxy, b"pong");

    sandbox_write.shutdown().await.unwrap();
    proxy_write.shutdown().await.unwrap();
    assert_eq!(proxy_read.read(&mut [0; 8]).await.unwrap(), 0);
    assert_eq!(sandbox_read.read(&mut [0; 8]).await.unwrap(), 0);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("relay should finish after both directions close")
        .unwrap();
}

#[tokio::test]
async fn network_relay_half_close_still_delivers_the_response() {
    let (task, sandbox, proxy) = open_relay().await;
    let (mut sandbox_read, mut sandbox_write) = tokio::io::split(sandbox);
    let (mut proxy_read, mut proxy_write) = tokio::io::split(proxy);

    sandbox_write.write_all(b"request-body").await.unwrap();
    sandbox_write.shutdown().await.unwrap();

    let mut request = [0; 12];
    proxy_read.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"request-body");
    assert_eq!(proxy_read.read(&mut [0; 1]).await.unwrap(), 0);

    proxy_write.write_all(b"response-body").await.unwrap();
    proxy_write.shutdown().await.unwrap();

    let mut response = [0; 13];
    sandbox_read.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response-body");
    assert_eq!(sandbox_read.read(&mut [0; 1]).await.unwrap(), 0);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("relay should finish after the half-close")
        .unwrap();
}

#[tokio::test]
async fn network_relay_keeps_idle_peers_open() {
    let (task, sandbox, proxy) = open_relay().await;
    tokio::time::sleep(RELAY_REVERSE_DRAIN + Duration::from_millis(300)).await;
    assert!(
        !task.is_finished(),
        "an idle relay must stay open past the rejection drain"
    );
    drop(sandbox);
    drop(proxy);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("relay should finish once both peers close")
        .unwrap();
}

#[tokio::test]
async fn network_relay_stops_on_response_error_without_draining_upload() {
    let fail = Arc::new(AtomicBool::new(false));
    let fail_write = Arc::clone(&fail);
    let (task, sandbox, mut proxy) = open_relay_with_boundary(move |boundary| {
        Box::new(ResponseFailure {
            inner: boundary,
            fail: fail_write,
        })
    })
    .await;
    let (_sandbox_read, sandbox_write) = tokio::io::split(sandbox);
    // Leave the proxy unread. A relay that keeps copying the body after the
    // response fails stays blocked on that full buffer.
    let (sent, writer) = spawn_upload(sandbox_write);
    wait_for_upload_progress(&sent).await;
    assert!(
        !writer.is_finished(),
        "upload ended before the response failed"
    );
    fail.store(true, Ordering::Release);
    proxy
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("response error should stop the relay without draining the upload")
        .unwrap();
    let written = writer.await.expect("upload writer");
    assert!(
        written < UPLOAD_LEN,
        "relay drained the upload after a response error ({written} bytes)"
    );
    drop(proxy);
}
