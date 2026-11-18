// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network clients that tests run inside a sandbox, and typed results for
//! them. Each runs in the sandbox, so the sandbox policy applies to it. File
//! system or system-call probes belong in a sibling crate.
//!
//! See "Writing a sandbox client" in `tests/testkit/README.md` for the
//! contract a client script follows.
//!
//! The clients run in a sandbox created from [`testkit::python_image`], with a
//! policy that lets [`testkit::PYTHON_BINARIES`] reach the target:
//!
//! ```ignore
//! use host_server_support::{HttpRecorder, TEST_HOST};
//! use sandbox_clients_support::{Request, http};
//! use testkit::{PYTHON_BINARIES, policy};
//!
//! let server = HttpRecorder::start("hello").await?;
//! let mut allowed = policy::base();
//! policy::allow(&mut allowed, "server", TEST_HOST, server.port, PYTHON_BINARIES);
//! let sandbox = cx
//!     .sandbox("probe")
//!     .image(testkit::python_image())
//!     .command(["sleep", "infinity"])
//!     .policy(allowed)
//!     .create_ready()
//!     .await?;
//! let reply = http(&sandbox, TEST_HOST, server.port, &Request::get("/")).await?;
//! testkit::ensure!(reply.status() == Some(200), "{reply:?}");
//! ```
//!
//! - [`connect`] opens a TCP connection and reports whether it connected,
//!   the errno it failed with, or a timeout, and how long it took.
//! - [`http`] sends a [`Request`], and [`http_raw`] sends bytes as they are.
//!   Both report how the connection went, the bytes that came back, and the
//!   parsed [`Response`].
//! - [`scripts`] holds the client scripts, for tests that run one with
//!   [`testkit::Sandbox::run_python`] and read its result with
//!   [`testkit::ExecOutput::last_json`]. Protocol clients, such as `GraphQL` or
//!   JSON-RPC ones, belong there too, so every suite can use them.
//!
//! Both probes use a raw socket. Sandboxes set no proxy variables, so this is
//! the same path a library such as `urllib` takes.

mod message;
mod probe;

pub use message::{Http, Request, Response};
pub use probe::{Connect, ConnectOutcome, ReadEnd, connect, http, http_raw};

/// Client scripts, as text to pass to [`testkit::Sandbox::run_python`].
pub mod scripts {
    /// Connects to a host and port, optionally sends bytes and reads the
    /// reply, and prints the outcome as one JSON line. [`crate::connect`] and
    /// [`crate::http`] run it and parse its output.
    pub const TCP_PROBE: &str = include_str!("../scripts/tcp_probe.py");
}
