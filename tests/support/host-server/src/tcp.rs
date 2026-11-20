// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use testkit::{Poll, Result, ResultExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::{MAX_REQUEST, READ_TIMEOUT, Server, WAIT_INTERVAL, WAIT_TIMEOUT, find};

/// How long a [`TcpServer::reply_when_idle`] connection waits for more bytes
/// before it answers.
const IDLE: Duration = Duration::from_millis(200);

/// A TCP server that records the bytes every connection sent, in arrival
/// order, for a test that checks raw bytes rather than parsed requests.
pub struct TcpServer {
    pub port: u16,
    received: Arc<Mutex<Vec<u8>>>,
    server: Server,
}

#[derive(Clone)]
enum Mode {
    Echo,
    ReplyWhenIdle(Arc<[u8]>),
}

impl TcpServer {
    /// Write back every byte a connection sends until it closes.
    pub async fn echo() -> Result<Self> {
        Self::start(Mode::Echo).await
    }

    /// Read until a connection is idle for 200 ms or closes, then write
    /// `reply` and close it. A test can send several requests at once and
    /// see all of them, since the server answers none before the last.
    pub async fn reply_when_idle(reply: impl Into<Vec<u8>>) -> Result<Self> {
        Self::start(Mode::ReplyWhenIdle(reply.into().into())).await
    }

    async fn start(mode: Mode) -> Result<Self> {
        let received = Arc::new(Mutex::new(Vec::new()));
        let task_received = Arc::clone(&received);
        let server =
            Server::start(move |stream| serve(stream, mode.clone(), Arc::clone(&task_received)))
                .await?;
        Ok(Self {
            port: server.port,
            received,
            server,
        })
    }

    /// The bytes the server has read so far.
    pub fn received(&self) -> Vec<u8> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The number of connections the server has accepted.
    pub fn connections(&self) -> usize {
        self.server.connections()
    }

    /// The bytes the server has read, once they contain `needle`.
    pub async fn wait_for(&self, needle: &[u8]) -> Result<Vec<u8>> {
        testkit::poll_until(
            &format!(
                "{:?} at the host server on port {}",
                String::from_utf8_lossy(needle),
                self.port
            ),
            WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                let received = self.received();
                Ok(if find(&received, needle).is_some() {
                    Poll::Ready(received)
                } else {
                    Poll::Pending(format!("{} byte(s)", received.len()))
                })
            },
        )
        .await
    }
}

/// Connect to `port` on the test host's loopback, send `request`, and return
/// what arrives until the other end closes. For a port the test reaches from
/// the host, such as one `openshell forward` listens on.
pub async fn exchange(port: u16, request: &[u8]) -> Result<Vec<u8>> {
    #[allow(
        clippy::disallowed_methods,
        reason = "standalone test support has no openshell-core dependency and enables TCP_NODELAY below"
    )]
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .context(format!("connect to 127.0.0.1:{port}"))?;
    stream.set_nodelay(true).context("enable TCP_NODELAY")?;
    stream
        .write_all(request)
        .await
        .context(format!("send to 127.0.0.1:{port}"))?;
    let mut reply = Vec::new();
    tokio::time::timeout(READ_TIMEOUT, stream.read_to_end(&mut reply))
        .await
        .map_err(|_| {
            testkit::Error::msg(format!(
                "127.0.0.1:{port} didn't close within {READ_TIMEOUT:?}; read {} byte(s)",
                reply.len()
            ))
        })?
        .context(format!("read from 127.0.0.1:{port}"))?;
    Ok(reply)
}

async fn serve(mut stream: TcpStream, mode: Mode, received: Arc<Mutex<Vec<u8>>>) {
    let _ = stream.set_nodelay(true);
    let idle = match mode {
        Mode::Echo => READ_TIMEOUT,
        Mode::ReplyWhenIdle(_) => IDLE,
    };
    let mut buffer = [0_u8; 4096];
    let mut total = 0;
    loop {
        let read = match tokio::time::timeout(idle, stream.read(&mut buffer)).await {
            Ok(Ok(read)) if read > 0 && total < MAX_REQUEST => read,
            _ => break,
        };
        total += read;
        received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(&buffer[..read]);
        if matches!(mode, Mode::Echo) && stream.write_all(&buffer[..read]).await.is_err() {
            return;
        }
    }
    if let Mode::ReplyWhenIdle(reply) = mode {
        let _ = stream.write_all(&reply).await;
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect(port: u16) -> TcpStream {
        #[allow(
            clippy::disallowed_methods,
            reason = "standalone test support has no openshell-core dependency and enables TCP_NODELAY below"
        )]
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }

    #[tokio::test]
    async fn echo_writes_back_and_records_bytes() {
        let server = TcpServer::echo().await.unwrap();
        let mut stream = connect(server.port).await;
        stream.write_all(&[0x00, 0xff, b'x']).await.unwrap();
        let mut echoed = [0_u8; 3];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, [0x00, 0xff, b'x']);
        assert_eq!(server.wait_for(b"x").await.unwrap(), [0x00, 0xff, b'x']);
        assert_eq!(server.connections(), 1);
    }

    #[tokio::test]
    async fn reply_when_idle_records_everything_before_replying() {
        let server = TcpServer::reply_when_idle(b"reply".to_vec()).await.unwrap();
        let mut stream = connect(server.port).await;
        stream.write_all(b"first ").await.unwrap();
        stream.write_all(b"second").await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
        assert_eq!(server.received(), b"first second");
    }

    #[tokio::test]
    async fn exchange_returns_the_reply_until_close() {
        let server = TcpServer::reply_when_idle(b"reply".to_vec()).await.unwrap();
        assert_eq!(exchange(server.port, b"hello").await.unwrap(), b"reply");
        assert_eq!(server.received(), b"hello");
    }
}
