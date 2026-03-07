// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: TCP port forwarding through a sandbox.
//!
//! Prerequisites:
//! - A running nemoclaw gateway (`nemoclaw gateway start`)
//! - The `nemoclaw` binary (built automatically from the workspace)

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use nemoclaw_e2e::harness::port::{find_free_port, wait_for_port};
use nemoclaw_e2e::harness::sandbox::SandboxGuard;

/// Python script that runs a single-threaded TCP echo server inside the
/// sandbox. It prints `echo-server-ready` to stdout once listening, which
/// the harness uses as the readiness marker.
fn echo_server_script(port: u16) -> String {
    format!(
        r"
import socket, sys, signal
signal.signal(signal.SIGHUP, signal.SIG_IGN)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
port = {port}
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', port))
sock.listen(1)
sock.settimeout(300)
print('echo-server-ready', flush=True)
try:
    while True:
        conn, _ = sock.accept()
        data = conn.recv(4096)
        if data:
            conn.sendall(b'echo:' + data)
        conn.close()
except (socket.timeout, OSError):
    pass
finally:
    sock.close()
"
    )
}

/// Create a sandbox with a TCP echo server, forward the port locally, send
/// data through it, and verify the echoed response.
#[tokio::test]
async fn port_forward_echo() {
    let port = find_free_port();
    let script = echo_server_script(port);

    // ---------------------------------------------------------------
    // Step 1 — Create a sandbox with the echo server running.
    // ---------------------------------------------------------------
    let mut guard =
        SandboxGuard::create_keep(&["python3", "-c", &script], "echo-server-ready")
            .await
            .expect("sandbox create with echo server");

    // ---------------------------------------------------------------
    // Step 2 — Start port forwarding in the background.
    // ---------------------------------------------------------------
    let mut forward_child = guard
        .spawn_forward(port)
        .expect("spawn port forward");

    // Wait for the local port to accept connections.
    wait_for_port("127.0.0.1", port, Duration::from_secs(30))
        .await
        .expect("local port should open for forwarding");

    // Give the SSH tunnel a moment to fully establish the direct-tcpip channel.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ---------------------------------------------------------------
    // Step 3 — Send data through the forwarded port and verify response.
    // ---------------------------------------------------------------
    let expected = "echo:hello-nav";
    let mut last_response = String::new();

    for attempt in 1..=5 {
        match try_echo(port).await {
            Ok(resp) if resp.starts_with(expected) => {
                last_response = resp;
                break;
            }
            Ok(resp) => {
                last_response = resp;
                eprintln!("attempt {attempt}: unexpected response '{last_response}', retrying...");
            }
            Err(e) => {
                eprintln!("attempt {attempt}: connection error: {e}, retrying...");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    assert!(
        last_response.starts_with(expected),
        "expected response starting with '{expected}', got '{last_response}'"
    );

    // ---------------------------------------------------------------
    // Cleanup — kill forward process, then sandbox guard handles the rest.
    // ---------------------------------------------------------------
    let _ = forward_child.kill().await;
    let _ = forward_child.wait().await;
    guard.cleanup().await;
}

/// Attempt to send `hello-nav\n` to the echo server and read the response.
async fn try_echo(port: u16) -> Result<String, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .map_err(|e| format!("connect: {e}"))?;

    stream
        .write_all(b"hello-nav\n")
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;

    let response = String::from_utf8_lossy(&buf[..n])
        .trim_end_matches(['\r', '\n'])
        .to_string();

    Ok(response)
}
