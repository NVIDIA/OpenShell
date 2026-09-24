// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Directional byte-stream closure and abort-preserving relay transport.

use crate::proto::{RelayClose, RelayCloseCode};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

/// Response FIN extension. Absence preserves legacy response EOF behavior.
pub const HALF_CLOSE_CAPABILITY: &str = "stream-half-close-v1";
/// `PeerRelay` response metadata confirms support along the downstream path.
pub const HALF_CLOSE_METADATA: &str = "openshell-stream-half-close";
/// Outbound frames are bounded independently of peer frame-limit rollout.
pub const CHUNK_SIZE: usize = 64 * 1024;

pub fn supports_half_close(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .any(|value| value == HALF_CLOSE_CAPABILITY)
}

pub fn capabilities() -> Vec<String> {
    vec![HALF_CLOSE_CAPABILITY.to_string()]
}

/// Payloads after the first request frame.
pub enum Payload {
    Data(Vec<u8>),
    HalfClose,
    Invalid,
}

pub trait Frame: Send + 'static {
    fn payload(self) -> Payload;
    fn data(data: Vec<u8>) -> Self;
    fn half_close() -> Self;
}

macro_rules! frame {
    ($name:ident, $module:ident) => {
        impl Frame for crate::proto::$name {
            fn payload(self) -> Payload {
                match self.payload {
                    Some(crate::proto::$module::Payload::Data(data)) => Payload::Data(data),
                    Some(crate::proto::$module::Payload::HalfClose(_)) => Payload::HalfClose,
                    _ => Payload::Invalid,
                }
            }
            fn data(data: Vec<u8>) -> Self {
                Self {
                    payload: Some(crate::proto::$module::Payload::Data(data)),
                }
            }
            fn half_close() -> Self {
                Self {
                    payload: Some(crate::proto::$module::Payload::HalfClose(
                        crate::proto::StreamHalfClose {},
                    )),
                }
            }
        }
    };
}
frame!(TcpForwardFrame, tcp_forward_frame);
frame!(RelayFrame, relay_frame);
frame!(PeerRelayFrame, peer_relay_frame);

pub fn close_status(close: &RelayClose) -> Status {
    let code = match RelayCloseCode::try_from(close.code) {
        Ok(RelayCloseCode::Cancelled) => tonic::Code::Cancelled,
        Ok(RelayCloseCode::DeadlineExceeded) => tonic::Code::DeadlineExceeded,
        Ok(RelayCloseCode::InvalidArgument) => tonic::Code::InvalidArgument,
        _ => tonic::Code::Unavailable,
    };
    Status::new(code, close.reason.clone())
}

pub fn close_message(channel_id: String, status: &Status) -> RelayClose {
    let code = match status.code() {
        tonic::Code::Cancelled => RelayCloseCode::Cancelled,
        tonic::Code::DeadlineExceeded => RelayCloseCode::DeadlineExceeded,
        tonic::Code::InvalidArgument => RelayCloseCode::InvalidArgument,
        _ => RelayCloseCode::Unavailable,
    };
    RelayClose {
        channel_id,
        reason: status.message().to_string(),
        code: code as i32,
    }
}

#[derive(Default, Debug)]
struct AbortState {
    error: Option<Status>,
    waiters: Vec<Waker>,
}

/// First observed abort wins; waking both directions interrupts backpressure.
#[derive(Clone, Default, Debug)]
pub struct AbortHandle(Arc<Mutex<AbortState>>);
impl AbortHandle {
    pub fn abort(&self, error: Status) -> Status {
        let waiters = {
            let mut state = self.0.lock().unwrap();
            if let Some(first) = &state.error {
                return first.clone();
            }
            state.error = Some(error.clone());
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
        error
    }
    fn poll_error(&self, cx: &Context<'_>) -> Option<Status> {
        let mut state = self.0.lock().unwrap();
        if let Some(error) = &state.error {
            return Some(error.clone());
        }
        if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            state.waiters.push(cx.waker().clone());
        }
        None
    }
    pub async fn aborted(&self) -> Status {
        std::future::poll_fn(|cx| self.poll_error(cx).map_or(Poll::Pending, Poll::Ready)).await
    }

    /// Observe aborts even after socket EOF or while a frame send is blocked.
    pub async fn run(
        &self,
        future: impl Future<Output = Result<(), Status>>,
    ) -> Result<(), Status> {
        let result = tokio::select! {
            biased;
            error = self.aborted() => Err(error),
            result = future => result,
        };
        result.map_err(|error| self.abort(error))
    }
}

/// Internal byte pipe that never converts a known terminal failure into EOF.
#[derive(Debug)]
pub struct RelayIo {
    stream: DuplexStream,
    abort: AbortHandle,
    half_close: bool,
}
impl RelayIo {
    pub fn pair() -> (Self, Self) {
        Self::pair_with_half_close(true)
    }

    /// Carry downstream capability with the pipe, including legacy fallback.
    pub fn pair_with_half_close(half_close: bool) -> (Self, Self) {
        let (a, b) = tokio::io::duplex(CHUNK_SIZE);
        let abort = AbortHandle::default();
        (
            Self {
                stream: a,
                abort: abort.clone(),
                half_close,
            },
            Self {
                stream: b,
                abort,
                half_close,
            },
        )
    }
    pub fn abort_handle(&self) -> AbortHandle {
        self.abort.clone()
    }

    pub fn supports_half_close(&self) -> bool {
        self.half_close
    }
}
impl AsyncRead for RelayIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(error) = self.abort.poll_error(cx) {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for RelayIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.abort.poll_error(cx) {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.abort.poll_error(cx) {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.abort.poll_error(cx) {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub fn io_status(error: io::Error) -> Status {
    error
        .get_ref()
        .and_then(|e| e.downcast_ref::<Status>())
        .cloned()
        .unwrap_or_else(|| Status::unavailable(error.to_string()))
}

/// Run a server-side bridge after consuming init. Both futures stay owned by
/// this call, so dropping/cancelling it cannot leave a detached input pump.
pub async fn serve<F, S, T>(
    mut inbound: S,
    socket: T,
    tx: &mpsc::Sender<Result<F, Status>>,
    half_close: bool,
) -> Result<(), Status>
where
    F: Frame,
    S: Stream<Item = Result<F, Status>> + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut read, mut write) = tokio::io::split(socket);
    let input = async {
        while let Some(frame) = inbound.next().await {
            tokio::task::consume_budget().await;
            let Payload::Data(data) = frame?.payload() else {
                return Err(Status::invalid_argument(
                    "only data is allowed after init; close requests with EOF",
                ));
            };
            write.write_all(&data).await.map_err(io_status)?;
        }
        write.shutdown().await.map_err(io_status)
    };
    let output = async {
        let mut buf = vec![0; CHUNK_SIZE];
        loop {
            let n = read.read(&mut buf).await.map_err(io_status)?;
            if n == 0 {
                break;
            }
            tx.send(Ok(F::data(buf[..n].to_vec())))
                .await
                .map_err(|_| Status::cancelled("response dropped"))?;
        }
        if half_close {
            tx.send(Ok(F::half_close()))
                .await
                .map_err(|_| Status::cancelled("response dropped"))?;
        }
        Ok::<_, Status>(())
    };
    tokio::pin!(input, output);
    let exchange = async {
        tokio::select! {
            result = &mut input => { result?; output.await }
            result = &mut output => { result?; if half_close { input.await } else { Ok(()) } }
        }
    };
    tokio::select! {
        biased;
        () = tx.closed() => Err(Status::cancelled("response dropped")),
        result = exchange => result,
    }
}

/// Client-side bridge. Sending EOF does not cancel receiving. A negotiated
/// response FIN shuts down only the destination writer; trailers remain read.
pub async fn client<F, S, R, W>(
    mut inbound: S,
    mut read: R,
    mut write: W,
    tx: mpsc::Sender<F>,
    half_close: bool,
) -> Result<(), Status>
where
    F: Frame,
    S: Stream<Item = Result<F, Status>> + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let input = async move {
        let mut buf = vec![0; CHUNK_SIZE];
        loop {
            let n = read.read(&mut buf).await.map_err(io_status)?;
            if n == 0 {
                return Ok::<_, Status>(());
            }
            tx.send(F::data(buf[..n].to_vec()))
                .await
                .map_err(|_| Status::unavailable("request stream closed"))?;
        }
    };
    let output = async {
        let mut closed = false;
        while let Some(frame) = inbound.next().await {
            tokio::task::consume_budget().await;
            match frame?.payload() {
                Payload::Data(data) if !closed => {
                    write.write_all(&data).await.map_err(io_status)?;
                    write.flush().await.map_err(io_status)?;
                }
                Payload::HalfClose if half_close && !closed => {
                    write.shutdown().await.map_err(io_status)?;
                    closed = true;
                }
                _ => {
                    return Err(Status::invalid_argument(
                        "invalid response frame or data after half-close",
                    ));
                }
            }
        }
        if !closed {
            write.shutdown().await.map_err(io_status)?;
        }
        Ok::<_, Status>(())
    };
    tokio::pin!(input, output);
    tokio::select! {
        biased;
        result = &mut output => result,
        result = &mut input => { result?; output.await }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{PeerRelayFrame, RelayFrame, TcpForwardFrame};
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_stream::wrappers::ReceiverStream;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = TcpStream::connect(listener.local_addr().unwrap());
        let (client, server) = tokio::join!(dial, listener.accept());
        (client.unwrap(), server.unwrap().0)
    }

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("bridge hung")
    }

    #[tokio::test]
    async fn request_fin_preserves_delayed_response() {
        bounded(async {
            let (bridge, mut target) = tcp_pair().await;
            let (input, rx) = mpsc::channel(4);
            let (output, mut responses) = mpsc::channel(4);
            let task = tokio::spawn(async move {
                serve::<TcpForwardFrame, _, _>(ReceiverStream::new(rx), bridge, &output, true).await
            });
            input.send(Ok(TcpForwardFrame::data(b"request".to_vec()))).await.unwrap();
            drop(input);
            let mut request = Vec::new();
            target.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            target.write_all(b"delayed response").await.unwrap();
            target.shutdown().await.unwrap();
            assert!(matches!(responses.recv().await.unwrap().unwrap().payload(), Payload::Data(data) if data == b"delayed response"));
            assert!(matches!(responses.recv().await.unwrap().unwrap().payload(), Payload::HalfClose));
            assert!(responses.recv().await.is_none());
            task.await.unwrap().unwrap();
        }).await;
    }

    #[tokio::test]
    async fn response_fin_preserves_later_requests_across_three_hops() {
        bounded(async {
            let (client_socket, mut application) = tcp_pair().await;
            let (supervisor_socket, mut target) = tcp_pair().await;
            let (front, mut peer_client) = RelayIo::pair();
            let (mut peer_owner, mut relay_server) = RelayIo::pair();
            let (forward_tx, forward_rx) = mpsc::channel(4);
            let (forward_out, forward_in) = mpsc::channel(4);
            let (peer_tx, peer_rx) = mpsc::channel(4);
            let (peer_out, peer_in) = mpsc::channel(4);
            let (relay_tx, relay_rx) = mpsc::channel(4);
            let (relay_out, relay_in) = mpsc::channel(4);
            let (client_r, client_w) = tokio::io::split(client_socket);
            let client_task = tokio::spawn(client::<TcpForwardFrame, _, _, _>(
                ReceiverStream::new(forward_in),
                client_r,
                client_w,
                forward_tx,
                true,
            ));
            let gateway = tokio::spawn(async move {
                serve::<TcpForwardFrame, _, _>(
                    ReceiverStream::new(forward_rx).map(Ok),
                    front,
                    &forward_out,
                    true,
                )
                .await
            });
            let peer = tokio::spawn(async move {
                let (r, w) = tokio::io::split(&mut peer_client);
                client::<PeerRelayFrame, _, _, _>(ReceiverStream::new(peer_in), r, w, peer_tx, true)
                    .await
            });
            let owner = tokio::spawn(async move {
                serve::<PeerRelayFrame, _, _>(
                    ReceiverStream::new(peer_rx).map(Ok),
                    &mut peer_owner,
                    &peer_out,
                    true,
                )
                .await
            });
            let relay = tokio::spawn(async move {
                serve::<RelayFrame, _, _>(
                    ReceiverStream::new(relay_rx).map(Ok),
                    &mut relay_server,
                    &relay_out,
                    true,
                )
                .await
            });
            let (target_r, target_w) = tokio::io::split(supervisor_socket);
            let supervisor = tokio::spawn(client::<RelayFrame, _, _, _>(
                ReceiverStream::new(relay_in),
                target_r,
                target_w,
                relay_tx,
                true,
            ));
            target.write_all(b"response").await.unwrap();
            target.shutdown().await.unwrap();
            let mut response = Vec::new();
            application.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
            application
                .write_all(b"request after response FIN")
                .await
                .unwrap();
            application.shutdown().await.unwrap();
            let mut request = Vec::new();
            target.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request after response FIN");
            for result in [
                client_task.await,
                gateway.await,
                peer.await,
                owner.await,
                relay.await,
                supervisor.await,
            ] {
                result.unwrap().unwrap();
            }
        })
        .await;
    }

    #[tokio::test]
    async fn legacy_downstream_drains_response_without_leaving_input_open() {
        bounded(async {
            let (bridge, mut downstream) = RelayIo::pair_with_half_close(false);
            let half_close = bridge.supports_half_close();
            let (_input, rx) = mpsc::channel::<Result<TcpForwardFrame, Status>>(1);
            let (output, mut responses) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                serve(ReceiverStream::new(rx), bridge, &output, half_close).await
            });
            downstream.write_all(b"legacy response").await.unwrap();
            drop(downstream);
            assert!(matches!(responses.recv().await.unwrap().unwrap().payload(), Payload::Data(data) if data == b"legacy response"));
            // The caller advertised FIN, but downstream cannot preserve input.
            // Drain bytes, then end the RPC without FIN or waiting for requests.
            assert!(responses.recv().await.is_none());
            task.await.unwrap().unwrap();
        }).await;
    }

    #[tokio::test]
    async fn legacy_response_eof_finishes_without_request_eof() {
        bounded(async {
            let (bridge, mut target) = tcp_pair().await;
            let (_input, rx) = mpsc::channel::<Result<TcpForwardFrame, Status>>(1);
            let (output, mut responses) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                serve(ReceiverStream::new(rx), bridge, &output, false).await
            });
            target.shutdown().await.unwrap();
            assert!(responses.recv().await.is_none());
            task.await.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn invalid_request_frames_are_protocol_errors() {
        for frame in [
            TcpForwardFrame::default(),
            TcpForwardFrame::half_close(),
            TcpForwardFrame {
                payload: Some(crate::proto::tcp_forward_frame::Payload::Init(
                    crate::proto::TcpForwardInit::default(),
                )),
            },
        ] {
            let (socket, _target) = tokio::io::duplex(1);
            let (out, _rx) = mpsc::channel(1);
            let error = bounded(serve(tokio_stream::iter([Ok(frame)]), socket, &out, true))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn response_fin_does_not_hide_trailers_or_invalid_frames() {
        for terminal in [
            Err(Status::deadline_exceeded("late deadline")),
            Ok(TcpForwardFrame::data(vec![1])),
            Ok(TcpForwardFrame::half_close()),
        ] {
            let expected = if terminal.is_err() {
                tonic::Code::DeadlineExceeded
            } else {
                tonic::Code::InvalidArgument
            };
            let (input, _rx) = mpsc::channel(1);
            let (read, _peer) = tokio::io::duplex(1);
            let error = bounded(client(
                tokio_stream::iter([Ok(TcpForwardFrame::half_close()), terminal]),
                read,
                tokio::io::sink(),
                input,
                true,
            ))
            .await
            .unwrap_err();
            assert_eq!(error.code(), expected);
        }
    }

    #[tokio::test]
    async fn abort_wakes_blocked_read_and_write_and_preserves_first_status() {
        bounded(async {
            let (mut left, mut right) = RelayIo::pair();
            let abort = left.abort_handle();
            left.write_all(&vec![0; CHUNK_SIZE]).await.unwrap();
            let blocked_write =
                tokio::spawn(async move { left.write_all(b"blocked").await.unwrap_err() });
            let blocked_read = tokio::spawn(async move {
                right.write_all(&vec![0; CHUNK_SIZE + 1]).await.unwrap_err()
            });
            abort.abort(Status::deadline_exceeded("deadline"));
            abort.abort(Status::cancelled("later cancellation"));
            assert_eq!(
                io_status(blocked_write.await.unwrap()).code(),
                tonic::Code::DeadlineExceeded
            );
            assert_eq!(
                io_status(blocked_read.await.unwrap()).code(),
                tonic::Code::DeadlineExceeded
            );
            let (mut a, _b) = RelayIo::pair();
            let abort = a.abort_handle();
            let read = tokio::spawn(async move { a.read(&mut [0]).await.unwrap_err() });
            abort.abort(Status::invalid_argument("invalid frame"));
            assert_eq!(
                io_status(read.await.unwrap()).code(),
                tonic::Code::InvalidArgument
            );
        })
        .await;
    }

    #[tokio::test]
    async fn dropping_response_cancels_a_backpressured_bridge() {
        bounded(async {
            let (bridge, mut target) = tokio::io::duplex(1);
            let (input, rx) = mpsc::channel(1);
            let (output, responses) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                serve::<TcpForwardFrame, _, _>(ReceiverStream::new(rx), bridge, &output, true).await
            });
            input
                .send(Ok(TcpForwardFrame::data(vec![0; 100])))
                .await
                .unwrap();
            target.write_all(b"a").await.unwrap();
            drop(responses);
            assert_eq!(
                task.await.unwrap().unwrap_err().code(),
                tonic::Code::Cancelled
            );
        })
        .await;
    }

    #[test]
    fn unknown_capabilities_and_close_codes_have_legacy_fallback() {
        assert!(!supports_half_close(&["future-feature".into()]));
        assert!(supports_half_close(&capabilities()));
        assert_eq!(
            close_status(&RelayClose {
                code: 999,
                ..Default::default()
            })
            .code(),
            tonic::Code::Unavailable
        );
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::InvalidArgument,
            tonic::Code::Unavailable,
        ] {
            assert_eq!(
                close_status(&close_message(
                    "channel".into(),
                    &Status::new(code, "reason")
                ))
                .code(),
                code
            );
        }
    }
}
