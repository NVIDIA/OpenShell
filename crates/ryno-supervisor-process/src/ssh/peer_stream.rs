// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bound SSH peer silence even while the session is blocked writing to its relay.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Only inbound bytes extend the deadline. SSH keepalive replies allow healthy
/// idle clients to retain their connections without sending application input.
pub(super) struct PeerStream<S> {
    stream: S,
    timeout: Duration,
    deadline: Pin<Box<Sleep>>,
}

impl<S> PeerStream<S> {
    pub(super) fn new(stream: S, timeout: Duration) -> Self {
        Self {
            stream,
            timeout,
            deadline: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH peer did not respond before the receive deadline",
            ));
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeerStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_deadline(cx)?;
        let before = buf.filled().len();
        match Pin::new(&mut self.stream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    let next = Instant::now() + self.timeout;
                    self.deadline.as_mut().reset(next);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeerStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Russh awaits packet writes outside its keepalive select. Polling here
        // makes an expired peer close even when the relay stops draining output.
        self.poll_deadline(cx)?;
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_deadline(cx)?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_deadline(cx)?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn blocked_write_expires_at_receive_deadline() {
        let (stream, _peer) = tokio::io::duplex(1);
        let mut stream = PeerStream::new(stream, Duration::from_mins(1));
        let started = Instant::now();
        let error = stream.write_all(b"ab").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_mins(1));
    }

    #[tokio::test(start_paused = true)]
    async fn only_received_bytes_extend_the_deadline() {
        let (stream, mut peer) = tokio::io::duplex(1);
        let mut stream = PeerStream::new(stream, Duration::from_mins(1));
        let started = Instant::now();
        tokio::time::advance(Duration::from_secs(40)).await;
        peer.write_all(b"r").await.unwrap();
        let mut reply = [0];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"r");
        tokio::time::advance(Duration::from_secs(40)).await;
        // A successful write must not renew peer liveness either.
        stream.write_all(b"a").await.unwrap();
        let error = stream.write_all(b"b").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(100));
    }
}
