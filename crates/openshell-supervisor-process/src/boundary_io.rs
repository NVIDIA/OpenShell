// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod [`BoundaryPortForward`] interface (RFC 0012 runtime contract).
//!
//! This is the live in-boundary port-forward for the in-pod placement. It lives
//! in this crate on purpose: the SSH server and supervisor session that consume
//! it are here, and so is the primitive it wraps
//! ([`connect_in_netns`](crate::ssh::connect_in_netns)). The interface trait
//! lives in the lower `openshell-isolation` crate, so this crate depends on the
//! trait (process -> isolation -> core, acyclic) and the SSH server drives a
//! `&dyn BoundaryPortForward` without depending on the backend.
//!
//! The SSH server and supervisor session are wired to this through the
//! `RunningBoundary::port_forward()` accessor: swapping in a kernel-separated
//! backend swaps this implementation (where `connect` tunnels into the guest)
//! and touches no consumer code.

use async_trait::async_trait;
use openshell_isolation::contract::{
    BackendError, BoundaryConn, BoundaryPortForward, LoopbackTarget,
};

/// In-pod loopback port-forward: connects to a loopback target from inside the
/// workload's network namespace via [`connect_in_netns`](crate::ssh::connect_in_netns).
pub struct NetnsPortForward {
    /// File descriptor of the boundary's network namespace, or `None` to
    /// connect from the supervisor's own namespace.
    pub netns_fd: Option<std::os::unix::io::RawFd>,
}

#[async_trait]
impl BoundaryPortForward for NetnsPortForward {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryConn, BackendError> {
        let addr = format!("{}:{}", target.host(), target.port());
        let stream = crate::ssh::connect_in_netns(&addr, self.netns_fd)
            .await
            .map_err(|e| BackendError::Process(format!("port-forward connect to {addr}: {e}")))?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Stands in for the SSH server's port-forward path: connect through the
    /// interface, write, read the echo. With `netns_fd: None` the connect happens in
    /// the supervisor's namespace, so this exercises the real primitive without
    /// requiring a network namespace.
    #[tokio::test]
    async fn port_forward_connects_and_round_trips() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
        });

        let pf = NetnsPortForward { netns_fd: None };
        let target =
            LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).expect("loopback target");
        let mut conn = pf.connect(target).await.expect("connect through interface");
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// Drive the port-forward interface through a generic `&dyn` consumer, proving a
    /// kernel-separated backend (tunneling into a guest) would use the same call.
    #[tokio::test]
    async fn port_forward_is_driven_via_dyn() {
        async fn forward_one(pf: &dyn BoundaryPortForward, target: LoopbackTarget) -> bool {
            pf.connect(target).await.is_ok()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let pf = NetnsPortForward { netns_fd: None };
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).unwrap();
        assert!(forward_one(&pf, target).await);
    }
}
