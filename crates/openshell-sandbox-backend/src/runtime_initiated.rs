// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor listener for runtime-initiated Sandbox Protocol connections.
//!
//! Only connection establishment is reversed. Each accepted socket completes the
//! same pinned TLS client handshake as a dialed connection before it is queued,
//! and every request still carries the Sandbox Protocol bearer token. A peer
//! address is never trusted.

use std::net::SocketAddr;
use std::time::Duration;

use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};
use tokio::sync::mpsc;

use crate::boundary_protocol::{
    SandboxRuntimeDescriptor, SandboxTlsClientConfig, SandboxTransport,
};

/// Unauthenticated sockets may hold at most this many TLS handshakes.
/// Further sockets are closed immediately rather than queued.
const MAX_PENDING_HANDSHAKES: usize = 8;
/// Upper bound on the time an unauthenticated peer may occupy a slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Authenticated connections not yet claimed by a client. The runtime keeps
/// one spare open, so a small bound only absorbs reconnect races.
const MAX_QUEUED_CONNECTIONS: usize = 2;

/// Accepts runtime-initiated connections for exactly one sandbox session.
///
/// Live channels own their streams; the queue holds only unclaimed,
/// authenticated spares, so no new connection can displace a live owner.
/// Dropping the listener closes the socket, pending handshakes, and spares.
#[derive(Debug)]
pub struct RuntimeInitiatedListener {
    tls: SandboxTlsClientConfig,
    spares: tokio::sync::Mutex<mpsc::Receiver<BoundaryDuplexStream>>,
    accept_task: tokio::task::AbortHandle,
}

impl RuntimeInitiatedListener {
    /// Bind the descriptor's listen address and start authenticating peers.
    pub fn bind(
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<std::sync::Arc<Self>, BackendError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            BackendError::Unavailable("runtime-initiated listener requires a Tokio runtime".into())
        })?;
        let _entered = runtime.enter();
        crate::runtime::validate_client_tls(&descriptor.tls)?;
        descriptor
            .transport
            .validate()
            .map_err(|error| BackendError::Descriptor(error.into()))?;
        let listener = match &descriptor.transport {
            SandboxTransport::RuntimeInitiatedTcp { listen_address, .. } => {
                Listener::Tcp(bind_tcp(*listen_address).map_err(unavailable)?)
            }
            #[cfg(unix)]
            SandboxTransport::RuntimeInitiatedUnix { socket_path } => {
                Listener::bind_unix(socket_path).map_err(unavailable)?
            }
            #[cfg(target_os = "linux")]
            SandboxTransport::RuntimeInitiatedVsock { guest_cid, port } => {
                Listener::bind_vsock(*guest_cid, *port).map_err(unavailable)?
            }
            _ => {
                return Err(BackendError::Descriptor(
                    "unsupported runtime-initiated transport on this platform".into(),
                ));
            }
        };
        Self::start(listener, &descriptor.tls)
    }

    fn start(
        listener: Listener,
        tls: &SandboxTlsClientConfig,
    ) -> Result<std::sync::Arc<Self>, BackendError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            BackendError::Unavailable("runtime-initiated listener requires a Tokio runtime".into())
        })?;
        let (sender, spares) = mpsc::channel(MAX_QUEUED_CONNECTIONS);
        let accept_task = runtime
            .spawn(accept_loop(listener, tls.clone(), sender))
            .abort_handle();
        tracing::info!("Runtime-initiated Sandbox Protocol listener ready");
        Ok(std::sync::Arc::new(Self {
            tls: tls.clone(),
            spares: tokio::sync::Mutex::new(spares),
            accept_task,
        }))
    }

    /// Wait for one authenticated runtime connection for `descriptor`. A
    /// listener bound for another session is refused.
    pub(crate) async fn accept(
        &self,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        if descriptor.tls != self.tls {
            return Err(BackendError::Descriptor(
                "runtime-initiated listener is bound to a different sandbox session".to_string(),
            ));
        }
        self.spares.lock().await.recv().await.ok_or_else(|| {
            BackendError::Unavailable("runtime-initiated control listener stopped".to_string())
        })
    }
}

impl Drop for RuntimeInitiatedListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

fn bind_tcp(address: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(64)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// Authenticate peers concurrently, bounded in count and time, and queue only
/// streams that completed the pinned handshake. A full queue closes the new
/// spare; the runtime dials again once a spare is used or lost.
async fn accept_loop(
    listener: Listener,
    tls: SandboxTlsClientConfig,
    spares: mpsc::Sender<BoundaryDuplexStream>,
) {
    let pending = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
    // Owned here so aborting this task also cancels every pending handshake.
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Descriptor exhaustion and similar errors are transient.
                        tracing::warn!(%error, "runtime-initiated control accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = pending.clone().try_acquire_owned() else {
                    tracing::debug!("runtime-initiated handshake limit reached; closing connection");
                    continue;
                };
                let tls = tls.clone();
                let spares = spares.clone();
                handshakes.spawn(async move {
                    let _permit = permit;
                    let authenticated = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        crate::runtime::authenticate_boundary_stream(&tls, stream),
                    )
                    .await;
                    match authenticated {
                        Ok(Ok(stream)) => {
                            if spares.try_send(stream).is_err() {
                                tracing::debug!("runtime-initiated spare queue full; closing connection");
                            }
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%error, "rejected unauthenticated runtime-initiated connection");
                        }
                        Err(_) => tracing::debug!("runtime-initiated TLS handshake timed out"),
                    }
                });
            }
            Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
        }
    }
}

fn unavailable(error: std::io::Error) -> BackendError {
    BackendError::Unavailable(format!("runtime-initiated control listener: {error}"))
}

#[derive(Debug)]
enum Listener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        path: std::path::PathBuf,
        inode: u64,
    },
    #[cfg(target_os = "linux")]
    Vsock {
        listener: tokio::io::unix::AsyncFd<socket2::Socket>,
        guest_cid: u32,
    },
}

impl Listener {
    #[cfg(unix)]
    fn bind_unix(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        // The driver owns the containing directory. Never replace a live socket,
        // another user's inode, or a non-socket (including symlinks).
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "refusing to replace unowned control socket",
                    ));
                }
                let probe =
                    socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
                probe.set_nonblocking(true)?;
                match probe.connect(&socket2::SockAddr::unix(path)?) {
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?;
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            "control socket is still active",
                        ));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        // Runtime and supervisor can have different UIDs. TLS pins the runtime;
        // the protected mount path is inaccessible to workload code.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        let inode = std::fs::symlink_metadata(path)?.ino();
        Ok(Self::Unix {
            listener,
            path: path.into(),
            inode,
        })
    }

    #[cfg(target_os = "linux")]
    fn bind_vsock(guest_cid: u32, port: u32) -> std::io::Result<Self> {
        let socket = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.bind(&socket2::SockAddr::vsock(libc::VMADDR_CID_ANY, port))?;
        socket.listen(64)?;
        Ok(Self::Vsock {
            listener: tokio::io::unix::AsyncFd::new(socket)?,
            guest_cid,
        })
    }

    async fn accept(&self) -> std::io::Result<BoundaryDuplexStream> {
        match self {
            Self::Tcp(listener) => {
                let (stream, _) = listener.accept().await?;
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                crate::runtime::enable_boundary_tcp_keepalive(&stream);
                Ok(Box::new(stream))
            }
            #[cfg(unix)]
            Self::Unix { listener, .. } => Ok(Box::new(listener.accept().await?.0)),
            #[cfg(target_os = "linux")]
            Self::Vsock {
                listener,
                guest_cid,
            } => loop {
                let mut ready = listener.readable().await?;
                match ready.try_io(|fd| fd.get_ref().accept()) {
                    Ok(Ok((socket, address))) => {
                        if address.as_vsock_address().map(|(cid, _)| cid) != Some(*guest_cid) {
                            continue;
                        }
                        socket.set_nonblocking(true)?;
                        let stream = tokio::net::UnixStream::from_std(
                            std::os::unix::net::UnixStream::from(socket),
                        )?;
                        return Ok(Box::new(stream));
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {}
                }
            },
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Self::Unix { path, inode, .. } = self {
            use std::os::unix::fs::MetadataExt;
            if std::fs::symlink_metadata(&*path).is_ok_and(|metadata| metadata.ino() == *inode) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
