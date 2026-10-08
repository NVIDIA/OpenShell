// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sandbox client of one relayed HTTP/1 exchange, and the watch that
//! notices when it goes away while its response is relayed.
//!
//! The relay writes the response through [`ClientLink`] while the watch reads
//! the client through the connection's buffer without consuming it, so a
//! client that leaves is noticed even while the upstream is silent. Bytes of
//! the client's next request stay buffered for that request's own policy
//! decision; once any arrive the watch stops, and a later close is noticed
//! only when a write fails. Under TLS the watch reads through the TLS layer,
//! which reports both `close_notify` and a bare FIN as a close.
//!
//! No transport tells a half-close from a full close, so the watch judges a
//! close by when it arrives:
//!
//! - A read error, such as a reset, ends the response at once.
//! - A close after the final response head reached the client ends the
//!   response at once.
//! - A close before the final head is a half-close. The response continues
//!   and the connection is not reused, but the response ends once it makes no
//!   progress for [`HALF_CLOSE_IDLE_TIMEOUT`].
//!
//! The watch looks for a close that is already readable when the final head
//! is written, so a close that arrives with the upstream head still counts
//! as a half-close. It cannot see a close while it is disarmed, so on the
//! live upload path a head written during the upload makes a close that
//! follows the body count as a close after the head.

use std::fmt;
use std::future::Future as _;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// How long a response to a half-closed client may make no progress: no
/// upstream read and no client write.
pub const HALF_CLOSE_IDLE_TIMEOUT: Duration =
    openshell_supervisor_middleware::HTTP_STREAM_IDLE_TIMEOUT;

/// How the client went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientGone {
    /// The client closed the connection after the final response head
    /// reached it.
    Closed,
    /// Reading from or writing to the client failed, as for a reset
    /// connection or a fatal TLS alert.
    Failed(std::io::ErrorKind),
    /// The client closed its sending side before the final response head,
    /// and the response then made no progress for
    /// [`HALF_CLOSE_IDLE_TIMEOUT`].
    HalfCloseIdle,
}

impl fmt::Display for ClientGone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("client closed the connection"),
            Self::Failed(kind) => write!(formatter, "client connection failed ({kind})"),
            Self::HalfCloseIdle => write!(
                formatter,
                "client half-closed the connection and the response was idle for {}s",
                HALF_CLOSE_IDLE_TIMEOUT.as_secs()
            ),
        }
    }
}

/// The client went away while its response was relayed. Nothing more was
/// written to it, and the upstream connection must not be reused.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("HTTP response ended: {gone}")]
pub struct DownstreamClosed {
    pub gone: ClientGone,
}

pub fn is_downstream_closed(report: &miette::Report) -> bool {
    report.downcast_ref::<DownstreamClosed>().is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Watch {
    /// The relay is still reading the request body.
    Disarmed,
    /// Watching through the connection buffer.
    Polling,
    /// Another reader consumes the client and reports how it ended.
    Reported,
    /// The client already sent more bytes, its next request. They stay
    /// buffered and the client is no longer watched.
    Busy,
    /// The client closed its sending side before the final head.
    HalfClosed,
    Gone(ClientGone),
}

struct State {
    watch: Watch,
    head_delivered: bool,
    wrote: bool,
    /// Last progress since the half-close.
    progressed_at: Instant,
    /// Waiter for arming or for a reported close.
    waker: Option<Waker>,
}

impl State {
    fn closed(&mut self) {
        self.watch = if self.head_delivered {
            Watch::Gone(ClientGone::Closed)
        } else {
            self.progressed_at = Instant::now();
            Watch::HalfClosed
        };
    }

    fn read_failed(&mut self, kind: std::io::ErrorKind) {
        // rustls reports a TCP close without `close_notify` this way.
        if kind == std::io::ErrorKind::UnexpectedEof {
            self.closed();
        } else {
            self.watch = Watch::Gone(ClientGone::Failed(kind));
        }
    }

    /// A write to the client failed, so the client is gone whatever the
    /// watch saw.
    fn write_failed(&mut self, kind: std::io::ErrorKind) {
        if !matches!(self.watch, Watch::Gone(_)) {
            self.watch = Watch::Gone(ClientGone::Failed(kind));
            self.wake();
        }
    }

    fn progressed(&mut self) {
        if self.watch == Watch::HalfClosed {
            self.progressed_at = Instant::now();
        }
    }

    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Shared access to the client of one exchange. The upload, the response
/// writer, and the watch each lock the client only inside one poll, never
/// across an await.
pub struct ClientLink<'c, C> {
    client: Mutex<&'c mut C>,
    state: Mutex<State>,
}

impl<'c, C> ClientLink<'c, C> {
    /// The watch starts disarmed, while the relay reads the request body.
    pub fn new(client: &'c mut C) -> Self {
        Self {
            client: Mutex::new(client),
            state: Mutex::new(State {
                watch: Watch::Disarmed,
                head_delivered: false,
                wrote: false,
                progressed_at: Instant::now(),
                waker: None,
            }),
        }
    }

    /// Start watching: the request body has been read.
    pub fn arm(&self) {
        self.arm_as(Watch::Polling);
    }

    /// Start watching through [`Self::reader`], which keeps consuming the
    /// client and reports how its stream ended.
    pub fn arm_reported(&self) {
        self.arm_as(Watch::Reported);
    }

    fn arm_as(&self, watch: Watch) {
        let mut state = lock(&self.state);
        if state.watch == Watch::Disarmed {
            state.watch = watch;
            state.wake();
        }
    }

    pub fn writer(&self) -> ClientWriter<'_, 'c, C> {
        ClientWriter { link: self }
    }

    pub fn reader(&self) -> ClientReader<'_, 'c, C> {
        ClientReader { link: self }
    }

    pub fn progress(&self) -> Progress<'_> {
        Progress(&self.state)
    }

    /// True once any response byte was written to the client.
    pub fn wrote_response(&self) -> bool {
        lock(&self.state).wrote
    }

    /// True when the client closed its sending side before the final head,
    /// so it sends no further request.
    pub fn half_closed(&self) -> bool {
        lock(&self.state).watch == Watch::HalfClosed
    }

    /// `error` as a [`DownstreamClosed`] when the client is gone, such as
    /// after a failed write to it, since the client caused it.
    pub fn downstream_closed_or(&self, error: miette::Report) -> miette::Report {
        if is_downstream_closed(&error) {
            return error;
        }
        let watch = lock(&self.state).watch;
        match watch {
            Watch::Gone(gone) => miette::Report::new(DownstreamClosed { gone }),
            _ => error,
        }
    }
}

impl<C: AsyncBufRead + Unpin> ClientLink<'_, C> {
    /// Resolves when the client is gone. Stays pending while the watch is
    /// disarmed and after the client sent its next request.
    pub async fn gone(&self) -> ClientGone {
        let mut idle = None;
        std::future::poll_fn(|cx| self.poll_gone(cx, &mut idle)).await
    }

    fn poll_gone(
        &self,
        cx: &mut Context<'_>,
        idle: &mut Option<Pin<Box<Sleep>>>,
    ) -> Poll<ClientGone> {
        let mut state = lock(&self.state);
        loop {
            match state.watch {
                Watch::Gone(gone) => return Poll::Ready(gone),
                Watch::Disarmed | Watch::Reported => {
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                Watch::Busy => return Poll::Pending,
                Watch::HalfClosed => {
                    // Progress moves the deadline; the timer catches up only
                    // when it fires.
                    let deadline = state.progressed_at + HALF_CLOSE_IDLE_TIMEOUT;
                    let sleep =
                        idle.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    if Instant::now() < deadline {
                        sleep.as_mut().reset(deadline);
                        continue;
                    }
                    state.watch = Watch::Gone(ClientGone::HalfCloseIdle);
                }
                Watch::Polling => {
                    if self.poll_client(&mut state, cx).is_pending() {
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    /// Read the client's buffer without consuming it. Pending while nothing
    /// is readable.
    fn poll_client(&self, state: &mut State, cx: &mut Context<'_>) -> Poll<()> {
        match Pin::new(&mut **lock(&self.client)).poll_fill_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(buffered)) if !buffered.is_empty() => state.watch = Watch::Busy,
            Poll::Ready(Ok(_)) => state.closed(),
            Poll::Ready(Err(error)) => state.read_failed(error.kind()),
        }
        Poll::Ready(())
    }

    /// The final (non-1xx) response head reached the client. A close that
    /// was already readable arrived before it.
    pub fn head_delivered(&self) {
        let mut state = lock(&self.state);
        if state.watch == Watch::Polling {
            // The noop waker is replaced by the task's own at the next poll
            // of `gone`.
            let _ = self.poll_client(&mut state, &mut Context::from_waker(Waker::noop()));
        }
        state.head_delivered = true;
    }
}

/// Records response progress for the watch.
#[derive(Clone, Copy)]
pub struct Progress<'l>(&'l Mutex<State>);

impl Progress<'_> {
    pub fn record(self) {
        lock(self.0).progressed();
    }
}

/// Upstream reader that records each read as response progress.
pub struct ProgressReader<'a, U> {
    pub upstream: &'a mut U,
    pub progress: Progress<'a>,
}

impl<U: AsyncRead + Unpin> AsyncRead for ProgressReader<'_, U> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let read = Pin::new(&mut *this.upstream).poll_read(cx, buf);
        if matches!(read, Poll::Ready(Ok(()))) && buf.filled().len() > filled {
            this.progress.record();
        }
        read
    }
}

/// Write access to the client for the response.
pub struct ClientWriter<'l, 'c, C> {
    link: &'l ClientLink<'c, C>,
}

impl<C: AsyncBufRead + Unpin> ClientWriter<'_, '_, C> {
    pub fn head_delivered(&self) {
        self.link.head_delivered();
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for ClientWriter<'_, '_, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let written = Pin::new(&mut **lock(&self.link.client)).poll_write(cx, buf);
        match &written {
            Poll::Ready(Ok(count)) if *count > 0 => {
                let mut state = lock(&self.link.state);
                state.wrote = true;
                state.progressed();
            }
            Poll::Ready(Err(error)) => lock(&self.link.state).write_failed(error.kind()),
            _ => {}
        }
        written
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let flushed = Pin::new(&mut **lock(&self.link.client)).poll_flush(cx);
        if let Poll::Ready(Err(error)) = &flushed {
            lock(&self.link.state).write_failed(error.kind());
        }
        flushed
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let shut = Pin::new(&mut **lock(&self.link.client)).poll_shutdown(cx);
        if let Poll::Ready(Err(error)) = &shut {
            lock(&self.link.state).write_failed(error.kind());
        }
        shut
    }
}

/// Read access to the client for the request body.
pub struct ClientReader<'l, 'c, C> {
    link: &'l ClientLink<'c, C>,
}

impl<C: AsyncRead + Unpin> AsyncRead for ClientReader<'_, '_, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled = buf.filled().len();
        let wanted = buf.remaining() > 0;
        let read = Pin::new(&mut **lock(&self.link.client)).poll_read(cx, buf);
        if let Poll::Ready(result) = &read {
            let mut state = lock(&self.link.state);
            if state.watch == Watch::Reported {
                match result {
                    Ok(()) if wanted && buf.filled().len() == filled => state.closed(),
                    Ok(()) => {}
                    Err(error) => state.read_failed(error.kind()),
                }
                if state.watch != Watch::Reported {
                    state.wake();
                }
            }
        }
        read
    }
}

/// Test client that receives a response and never sends or closes, so the
/// client watch never fires.
#[cfg(test)]
pub struct ReceivingClient<W>(pub W);

#[cfg(test)]
impl<W: Unpin> AsyncRead for ReceivingClient<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

#[cfg(test)]
impl<W: Unpin> AsyncBufRead for ReceivingClient<W> {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        Poll::Pending
    }

    fn consume(self: Pin<&mut Self>, _amt: usize) {}
}

#[cfg(test)]
impl<W: AsyncWrite + Unpin> AsyncWrite for ReceivingClient<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use super::*;

    async fn settled(link: &ClientLink<'_, BufReader<DuplexStream>>) -> Option<ClientGone> {
        tokio::time::timeout(Duration::from_millis(50), link.gone())
            .await
            .ok()
    }

    #[tokio::test]
    async fn a_disarmed_watch_ignores_a_close() {
        let (peer, client) = tokio::io::duplex(64);
        let mut client = BufReader::new(client);
        let link = ClientLink::new(&mut client);
        drop(peer);
        assert_eq!(settled(&link).await, None);
        link.arm();
        assert_eq!(settled(&link).await, None, "a close before the head");
        assert!(link.half_closed());
    }

    #[tokio::test]
    async fn a_close_after_the_head_is_gone_at_once() {
        let (mut peer, client) = tokio::io::duplex(64);
        let mut client = BufReader::new(client);
        let link = ClientLink::new(&mut client);
        link.arm();
        link.writer()
            .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .await
            .expect("write head");
        link.writer().head_delivered();
        assert_eq!(settled(&link).await, None);
        peer.shutdown().await.expect("client close");
        assert_eq!(settled(&link).await, Some(ClientGone::Closed));
        assert!(link.wrote_response());
    }

    #[tokio::test]
    async fn the_next_request_stays_buffered_and_ends_the_watch() {
        let (mut peer, client) = tokio::io::duplex(64);
        let mut client = BufReader::new(client);
        {
            let link = ClientLink::new(&mut client);
            link.arm();
            link.writer().head_delivered();
            peer.write_all(b"GET /next").await.expect("next request");
            peer.shutdown().await.expect("client close");
            assert_eq!(settled(&link).await, None);
        }
        let mut next = Vec::new();
        client.read_to_end(&mut next).await.expect("read rest");
        assert_eq!(next, b"GET /next");
    }

    #[tokio::test]
    async fn a_reader_reports_how_the_client_stream_ended() {
        let (mut peer, client) = tokio::io::duplex(64);
        let mut client = BufReader::new(client);
        let link = ClientLink::new(&mut client);
        link.arm_reported();
        link.writer().head_delivered();
        peer.write_all(b"rest of the body").await.expect("body");
        drop(peer);
        assert_eq!(settled(&link).await, None, "the watch does not read");
        let mut discarded = Vec::new();
        link.reader()
            .read_to_end(&mut discarded)
            .await
            .expect("drain");
        assert_eq!(settled(&link).await, Some(ClientGone::Closed));
    }

    #[test]
    fn unexpected_eof_is_a_close_and_other_errors_fail() {
        let mut state = State {
            watch: Watch::Polling,
            head_delivered: true,
            wrote: false,
            progressed_at: Instant::now(),
            waker: None,
        };
        state.read_failed(ErrorKind::UnexpectedEof);
        assert_eq!(state.watch, Watch::Gone(ClientGone::Closed));
        state.watch = Watch::Polling;
        state.read_failed(ErrorKind::ConnectionReset);
        assert_eq!(
            state.watch,
            Watch::Gone(ClientGone::Failed(ErrorKind::ConnectionReset))
        );
    }
}
