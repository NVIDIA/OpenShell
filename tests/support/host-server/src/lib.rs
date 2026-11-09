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

mod http;
mod websocket;

use std::time::Duration;

use testkit::{Error, Result, ResultExt as _};
use tokio::net::TcpListener;

pub use http::{HttpRecorder, Request};
pub use websocket::WebSocketRecorder;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_INTERVAL: Duration = Duration::from_millis(100);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST: usize = 1024 * 1024;

async fn bind() -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("0.0.0.0", 0))
        .await
        .map_err(|error| Error::from_error(&error))
        .context("bind a host server")?;
    let port = listener
        .local_addr()
        .map_err(|error| Error::from_error(&error))
        .context("read the host server's address")?
        .port();
    Ok((listener, port))
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
