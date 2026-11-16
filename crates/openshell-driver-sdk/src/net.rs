// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Socket helpers shared by core and the compute drivers.

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

/// Connect to `addr`, then enable `TCP_NODELAY` on a best-effort basis, propagating
/// any errors from `TcpStream::connect`.
///
/// The returned stream is not *guaranteed* to have `TCP_NODELAY` set.
pub async fn connect_tcp_nodelay_best_effort(
    addr: impl tokio::net::ToSocketAddrs,
) -> std::io::Result<TcpStream> {
    #[allow(clippy::disallowed_methods, reason = "the one sanctioned async dial")]
    let stream = TcpStream::connect(addr).await?;
    set_tcp_nodelay_best_effort(&stream);
    Ok(stream)
}

/// Blocking counterpart of [`connect_tcp_nodelay_best_effort`] for threads that
/// cannot use the async helper, such as a `setns` worker.
pub fn connect_std_tcp_nodelay_best_effort(
    addr: impl std::net::ToSocketAddrs,
) -> std::io::Result<std::net::TcpStream> {
    #[allow(
        clippy::disallowed_methods,
        reason = "the one sanctioned blocking dial"
    )]
    let stream = std::net::TcpStream::connect(addr)?;
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "failed to set TCP_NODELAY");
    }
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
        #[allow(clippy::disallowed_methods, reason = "needs a stream without nodelay")]
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

        let stream = connect_tcp_nodelay_best_effort(addr)
            .await
            .expect("connect");
        assert!(stream.nodelay().expect("query TCP_NODELAY"));
    }
}
