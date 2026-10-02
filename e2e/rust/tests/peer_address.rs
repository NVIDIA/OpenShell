// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that a workload accepting a connection learns who connected.
//!
//! `accept(fd, &addr, &len)` asks the kernel to write the peer address into
//! the caller's buffer. On kernels without
//! `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` the sandbox's seccomp broker
//! cannot write into workload memory and fails closed, so the workload sees
//! `EOPNOTSUPP` instead of a connection. RHEL 9 and its derivatives ship such
//! a kernel, and server frameworks that read the peer address are unusable
//! there.
//!
//! This test is implementation-agnostic: it asserts what the workload
//! observes, not how the sandbox arranges for it. On a kernel that supports
//! task-memory writes the broker answers directly; on one that does not, a
//! preloaded shim rewrites the call. Either way the peer must be reported
//! correctly.

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

/// Python script that connects to its own listener and reports the peer.
///
/// Both ends live inside the sandbox, which keeps the test independent of
/// port forwarding and exercises the directly connected socket case. The
/// script reports `errno` rather than raising so a fail-closed broker
/// produces a diagnosable result instead of a bare non-zero exit.
fn peer_address_script() -> &'static str {
    r#"
import json, socket

result = {}
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    result["listen_port"] = server.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(("127.0.0.1", result["listen_port"]))
    result["client_port"] = client.getsockname()[1]

    # The call under test: socket.accept() passes an address buffer through
    # libc, which is the shape a fail-closed broker rejects.
    conn, peer = server.accept()
    result["accept_peer_host"] = peer[0]
    result["accept_peer_port"] = peer[1]
    result["getpeername_port"] = conn.getpeername()[1]

    # Prove the accepted descriptor is the live connection, not just a
    # plausible-looking number.
    conn.sendall(b"ping")
    result["echo"] = client.recv(4).decode()
    result["accept"] = "ok"
except OSError as e:
    result["accept"] = f"error:{e.errno}:{e}"

print(json.dumps(result), flush=True)
"#
}

/// A workload that accepts a connection must learn the connecting peer's
/// address, and that address must be the client's, not the listener's.
#[tokio::test]
async fn accept_reports_the_connecting_peer() {
    let guard = SandboxGuard::create(&["--", "python3", "-c", peer_address_script()])
        .await
        .expect("sandbox create");

    let json_line = guard
        .create_output
        .lines()
        .find(|l| l.contains("\"accept\""))
        .unwrap_or_else(|| panic!("no accept JSON in output:\n{}", guard.create_output));

    let parsed: serde_json::Value = serde_json::from_str(json_line.trim())
        .unwrap_or_else(|e| panic!("failed to parse JSON '{json_line}': {e}"));

    let outcome = parsed["accept"].as_str().unwrap();
    assert_eq!(
        outcome, "ok",
        "accept() with a peer-address buffer failed. errno 95 (EOPNOTSUPP) means the \
         seccomp broker fell back to its fail-closed path and no compatibility shim \
         covered the call.\nFull output:\n{}",
        guard.create_output
    );

    let listen_port = parsed["listen_port"].as_u64().unwrap();
    let client_port = parsed["client_port"].as_u64().unwrap();
    let accept_port = parsed["accept_peer_port"].as_u64().unwrap();
    let getpeername_port = parsed["getpeername_port"].as_u64().unwrap();

    assert_eq!(
        accept_port, client_port,
        "accept() reported peer port {accept_port}, but the client is bound to {client_port}."
    );
    // Reporting the listener's own address is the specific wrong answer a
    // broker produces when it substitutes the socket it knows about.
    assert_ne!(
        accept_port, listen_port,
        "accept() reported the listener's own port {listen_port} as the peer."
    );
    assert_eq!(
        parsed["accept_peer_host"].as_str().unwrap(),
        "127.0.0.1",
        "unexpected peer host for a loopback connection"
    );
    assert_eq!(
        getpeername_port, client_port,
        "getpeername() on the accepted socket reported {getpeername_port}, expected {client_port}."
    );
    assert_eq!(
        parsed["echo"].as_str().unwrap(),
        "ping",
        "the accepted descriptor did not carry the connection"
    );
}
