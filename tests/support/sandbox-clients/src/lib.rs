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
//! use host_server_support::{HttpRecorder, TEST_HOST, allow_host};
//! use sandbox_clients_support::{Request, http};
//! use testkit::policy;
//!
//! let server = HttpRecorder::start("hello").await?;
//! let mut allowed = policy::base();
//! allow_host(&mut allowed, "server", server.port);
//! let sandbox = cx.python_sandbox("probe", allowed).create_ready().await?;
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

    /// Serves HTTP on 127.0.0.1 and fetches from it, and prints whether the
    /// environment has proxy variables and the payload it got.
    pub const LOCALHOST_CLIENT: &str = include_str!("../scripts/localhost_client.py");

    /// Closes listeners and exits a child that owns one, and fails unless the
    /// port then refuses connections and can be bound again. Prints the child
    /// listener's address and socket inode.
    pub const LISTENER_LIFETIME_PROBE: &str = include_str!("../scripts/listener_lifetime_probe.py");

    /// A sandbox command that opens an inheritable socket, writes its inode to
    /// `/sandbox/preconnect-inode`, and sleeps.
    pub const PRECONNECT_OWNER: &str = include_str!("../scripts/preconnect_owner.py");

    /// Fails if the process holds the socket whose inode is its argument.
    pub const SOCKET_NOT_INHERITED: &str = include_str!("../scripts/socket_not_inherited.py");

    /// Holds a keep-alive connection to a host and port across a policy
    /// reload: prints `ready`, waits for a line on stdin, then prints the
    /// status of a second request on the same connection.
    pub const RELOAD_KEEP_ALIVE_CLIENT: &str =
        include_str!("../scripts/reload_keep_alive_client.py");

    /// Runs an MCP client for each protocol revision it's given, and prints
    /// `MCP_OK version=<version>` after each passes.
    pub const MCP_CLIENT: &str = include_str!("../scripts/mcp_client.py");

    /// A TCP server on 127.0.0.1 at its argument's port that answers each
    /// connection with `echo:` and the bytes it read.
    pub const ECHO_SERVER: &str = include_str!("../scripts/echo_server.py");

    /// Upgrades to WebSocket, sends one binary frame, and waits briefly for a
    /// reply.
    pub const WEBSOCKET_BINARY_CLIENT: &str = include_str!("../scripts/websocket_binary_client.py");

    /// Upgrades to WebSocket, sends the token in `E2E_GATING_TOKEN` in one text
    /// frame, and prints the server's text reply.
    pub const WEBSOCKET_TEXT_CLIENT: &str = include_str!("../scripts/websocket_text_client.py");

    /// A bash script, not Python: sends the token in `BOUND_TOKEN_A` to a
    /// bound endpoint, another provider's endpoint and an unbound path, and
    /// prints the first body and the other two statuses.
    pub const BOUND_CREDENTIAL_CLIENT: &str = include_str!("../scripts/bound_credential_client.sh");
}
