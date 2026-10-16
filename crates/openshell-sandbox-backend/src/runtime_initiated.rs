// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor listener for runtime-initiated Sandbox Protocol connections.
//!
//! Only the TCP dial direction is reversed. Each accepted socket completes the
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
        match descriptor.transport {
            SandboxTransport::RuntimeInitiatedTcp { listen_address, .. }
                if listen_address.port() != 0 =>
            {
                Self::bind_address(listen_address, &descriptor.tls)
            }
            _ => Err(BackendError::Descriptor(
                "runtime-initiated listener requires a nonzero listen port".to_string(),
            )),
        }
    }

    pub(crate) fn bind_address(
        address: SocketAddr,
        tls: &SandboxTlsClientConfig,
    ) -> Result<std::sync::Arc<Self>, BackendError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            BackendError::Unavailable("runtime-initiated listener requires a Tokio runtime".into())
        })?;
        // Fail before opening a socket that could never authenticate a peer.
        crate::runtime::validate_client_tls(tls)?;
        let _entered = runtime.enter();
        let listener = bind_tcp(address).map_err(|error| {
            BackendError::Unavailable(format!(
                "bind runtime-initiated control listener {address}: {error}"
            ))
        })?;
        let local_address = listener.local_addr().map_err(|error| {
            BackendError::Unavailable(format!("read control listener address: {error}"))
        })?;
        let (sender, spares) = mpsc::channel(MAX_QUEUED_CONNECTIONS);
        let accept_task = runtime
            .spawn(accept_loop(listener, tls.clone(), sender))
            .abort_handle();
        tracing::info!(%local_address, "Runtime-initiated Sandbox Protocol listener ready");
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
    listener: tokio::net::TcpListener,
    tls: SandboxTlsClientConfig,
    spares: mpsc::Sender<BoundaryDuplexStream>,
) {
    let pending = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
    // Owned here so aborting this task also cancels every pending handshake.
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Descriptor exhaustion and similar errors are transient.
                        tracing::warn!(%error, "runtime-initiated control accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = pending.clone().try_acquire_owned() else {
                    tracing::debug!(%peer, "runtime-initiated handshake limit reached; closing connection");
                    continue;
                };
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                crate::runtime::enable_boundary_tcp_keepalive(&stream);
                let tls = tls.clone();
                let spares = spares.clone();
                handshakes.spawn(async move {
                    let _permit = permit;
                    let authenticated = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        crate::runtime::authenticate_boundary_stream(&tls, Box::new(stream)),
                    )
                    .await;
                    match authenticated {
                        Ok(Ok(stream)) => {
                            if spares.try_send(stream).is_err() {
                                tracing::debug!(%peer, "runtime-initiated spare queue full; closing connection");
                            }
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%peer, %error, "rejected unauthenticated runtime-initiated connection");
                        }
                        Err(_) => tracing::debug!(%peer, "runtime-initiated TLS handshake timed out"),
                    }
                });
            }
            Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
        }
    }
}
