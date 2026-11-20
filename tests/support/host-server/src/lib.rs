// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Servers on the test host that sandboxes reach through
//! `host.openshell.internal`, and that record what arrived, so a test can
//! check what the supervisor forwarded upstream.
//!
//! The servers listen on every host address, since drivers map
//! `host.openshell.internal` to different ones, and stop when dropped. They
//! run where the tests run, so a gateway whose sandboxes can't reach the test
//! host, such as one on a remote cluster, can't run tests that use them.
//!
//! - [`HttpRecorder`] answers HTTP requests with a fixed body or a handler's
//!   [`Response`], and records each parsed [`Request`]. It serves HTTPS with
//!   a certificate from a [`TestCa`], and listens on a random free port unless
//!   [`HttpRecorder::builder`] names one.
//! - [`WebSocketRecorder`] completes the WebSocket handshake and records the
//!   frames that arrive.
//! - [`TcpServer`] records raw bytes, and echoes them or answers once the
//!   client goes idle.
//! - [`free_port`] finds a port nothing listens on, and [`exchange`] sends
//!   bytes to a loopback port and reads the reply.

mod http;
mod tcp;
mod tls;
mod websocket;

use std::time::Duration;

use testkit::{Result, ResultExt as _};
use tokio::net::TcpListener;

pub use http::{HttpRecorder, HttpRecorderBuilder, Request, Response};
pub use tcp::{TcpServer, exchange};
pub use tls::{ADDITIONAL_CA_CERT_ENV, ADDITIONAL_CA_KEY_ENV, Identity, TestCa};
pub use websocket::{TEXT_REPLY, WebSocketRecorder};

/// The name a sandbox reaches these servers by.
pub const TEST_HOST: &str = "host.openshell.internal";

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_INTERVAL: Duration = Duration::from_millis(100);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST: usize = 1024 * 1024;

/// Listen on every host address at `port`, or at a random free port for 0.
async fn bind(port: u16) -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .context(if port == 0 {
            "bind a host server".to_string()
        } else {
            format!("bind a host server on port {port}")
        })?;
    let port = listener
        .local_addr()
        .context("read the host server's address")?
        .port();
    Ok((listener, port))
}

/// A port that nothing on the test host listened on when this returned.
pub async fn free_port() -> Result<u16> {
    let (_listener, port) = bind(0).await?;
    Ok(port)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}
