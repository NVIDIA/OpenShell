// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loopback HTTP server for cloud metadata emulators.
//!
//! Binds a TCP listener inside the sandbox network namespace so that
//! cloud SDKs that bypass `HTTP_PROXY` (e.g. Go's
//! `cloud.google.com/go/compute/metadata`) can reach the emulator via
//! direct TCP.
//!
//! The server is generic over [`MetadataHandler`] — any cloud provider
//! that needs an instance metadata emulator can implement the trait.

use miette::Result;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tracing::{debug, warn};

const MAX_REQUEST_BYTES: usize = 4096;
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Handler for cloud metadata HTTP requests.
///
/// Implementors receive the parsed HTTP method, path, raw request bytes,
/// and a bidirectional stream to write the response. The handler owns the
/// response format (status, headers, body) — the server only does TCP
/// accept and HTTP request-line parsing.
pub trait MetadataHandler: Send + Sync + 'static {
    fn handle<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        method: &str,
        path: &str,
        request: &[u8],
        stream: &mut S,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Bind a TCP listener inside the sandbox network namespace.
///
/// Uses a dedicated OS thread (not `spawn_blocking`) to avoid namespace
/// contamination of the tokio blocking pool. See `ssh.rs::connect_in_netns`
/// for the same pattern.
///
/// # Safety contract
///
/// The caller must ensure `netns_fd` remains valid (not closed) until this
/// function returns. In practice, `NetworkNamespace` owns the fd and outlives
/// the sandbox — but new call sites must verify this invariant.
#[cfg(target_os = "linux")]
pub async fn bind_in_netns(
    addr: &str,
    netns_fd: std::os::unix::io::RawFd,
) -> std::io::Result<TcpListener> {
    let addr = addr.to_string();
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> std::io::Result<std::net::TcpListener> {
            // SAFETY: setns is safe to call; this is a dedicated thread that
            // exits after binding. The thread's namespace state does not
            // contaminate any thread pool.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            std::net::TcpListener::bind(&addr)
        })();
        let _ = tx.send(result);
    });

    let std_listener = rx
        .await
        .map_err(|_| std::io::Error::other("metadata server bind thread panicked"))??;
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

/// Run the metadata server accept loop.
///
/// Signals `ready_tx` with the bound address before entering the loop.
/// Returns when the listener encounters a fatal error or the runtime shuts down.
pub async fn run<H: MetadataHandler>(
    listener: TcpListener,
    handler: H,
    ready_tx: oneshot::Sender<SocketAddr>,
) {
    let local_addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("metadata server failed to get local address: {e}");
            return;
        }
    };

    let _ = ready_tx.send(local_addr);

    let handler = Arc::new(handler);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };

        match listener.accept().await {
            Ok((stream, _addr)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(handler.as_ref(), stream).await {
                        debug!("metadata server connection error: {e}");
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                warn!("metadata server accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn handle_connection<H: MetadataHandler>(
    handler: &H,
    mut stream: tokio::net::TcpStream,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let mut used = 0;
    let deadline = tokio::time::sleep(READ_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = stream.read(&mut buf[used..]) => {
                let n = result.map_err(|e| miette::miette!("{e}"))?;
                if n == 0 {
                    return Ok(());
                }
                used += n;
                if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if used >= buf.len() {
                    let _ = stream
                        .write_all(b"HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return Ok(());
                }
            }
            () = &mut deadline => {
                return Ok(());
            }
        }
    }
    let request = String::from_utf8_lossy(&buf[..used]);
    let request_line = request.split("\r\n").next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    tokio::time::timeout(
        READ_TIMEOUT,
        handler.handle(method, path, &buf[..used], &mut stream),
    )
    .await
    .unwrap_or_else(|_| {
        debug!(method, path, "metadata handler timed out");
        Ok(())
    })
}
