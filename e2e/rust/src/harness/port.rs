// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TCP port utilities for e2e tests.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::{interval, timeout};

/// Wait for a TCP port to accept connections.
///
/// Polls once per second until either a connection succeeds or the timeout
/// elapses. Returns `Ok(())` on success, `Err` on timeout.
///
/// # Errors
///
/// Returns an error if the port does not accept a connection within `max_wait`.
pub async fn wait_for_port(host: &str, port: u16, max_wait: Duration) -> Result<(), String> {
    let addr = format!("{host}:{port}");

    let result = timeout(max_wait, async {
        let mut tick = interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            if TcpStream::connect(&addr).await.is_ok() {
                return;
            }
        }
    })
    .await;

    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(format!(
            "port {port} on {host} did not accept connections within {max_wait:?}"
        )),
    }
}

/// Find an available TCP port by binding to port 0.
///
/// The OS assigns an ephemeral port which is returned. The listener is dropped
/// immediately, freeing the port for use by the test. There is a small TOCTOU
/// window, but it is acceptable for test code.
///
/// # Panics
///
/// Panics if the OS cannot allocate an ephemeral port.
pub fn find_free_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind to port 0");
    listener
        .local_addr()
        .expect("local_addr after bind")
        .port()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_free_port_returns_nonzero() {
        let port = find_free_port();
        assert_ne!(port, 0);
    }

    #[tokio::test]
    async fn wait_for_port_succeeds_when_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        wait_for_port("127.0.0.1", port, Duration::from_secs(5))
            .await
            .expect("should connect to listening port");
    }

    #[tokio::test]
    async fn wait_for_port_times_out_when_nothing_listens() {
        // Port 1 is almost certainly not listening and requires root.
        let result = wait_for_port("127.0.0.1", 1, Duration::from_secs(2)).await;
        assert!(result.is_err());
    }
}
