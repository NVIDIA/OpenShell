// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! IP classification and TCP socket tuning.

pub use openshell_policy_primitives::net::*;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Enable `TCP_NODELAY` on a stream, logging (not returning) any failure.
///
/// Disabling Nagle's algorithm keeps small writes from waiting on delayed ACKs.
/// It's a latency optimization: if it fails the connection still works, just a
/// bit slower, so there is nothing for the caller to act on — we log and move on.
pub fn set_tcp_nodelay_best_effort(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "failed to set TCP_NODELAY");
    }
}

/// Connect to `addrs`, then enable `TCP_NODELAY` on a best-effort basis, propagating
/// any errors from `TcpStream::connect`.
///
/// The returned stream is not *guaranteed* to have `TCP_NODELAY` set.
pub async fn connect_tcp_nodelay_best_effort(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(addrs).await?;
    set_tcp_nodelay_best_effort(&stream);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- tcp_nodelay helpers --

    #[tokio::test]
    async fn set_tcp_nodelay_best_effort_enables_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let stream = TcpStream::connect(addr).await.expect("connect");

        set_tcp_nodelay_best_effort(&stream);
        assert!(stream.nodelay().expect("query TCP_NODELAY"));
    }

    #[tokio::test]
    async fn connect_tcp_nodelay_best_effort_sets_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let stream = connect_tcp_nodelay_best_effort(&[addr])
            .await
            .expect("connect");
        assert!(stream.nodelay().expect("query TCP_NODELAY"));
    }
}
