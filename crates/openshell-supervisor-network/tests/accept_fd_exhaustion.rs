// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Subprocess-isolated integration test: lowers `RLIMIT_NOFILE`, induces
//! EMFILE on `accept()`, releases file descriptors, and verifies the
//! listener recovers and accepts a subsequent connection.
//!
//! Uses blocking I/O in the child to surface EMFILE reliably across
//! platforms (tokio's async accept may swallow EMFILE on kqueue-based
//! systems). The proxy's retry logic is validated by the unit tests for
//! `handle_accept_error`; this test validates the OS-level precondition
//! that recovery is possible after FD exhaustion clears.
//!
//! Runs in a child process so the test runner's process-wide resource
//! limits are not affected.

#![cfg(unix)]
#![allow(unsafe_code, reason = "setrlimit requires unsafe")]

use std::env;
use std::io::Read;
use std::io::Write;
use std::process::Command;

const CHILD_SENTINEL: &str = "__ACCEPT_FD_EXHAUSTION_CHILD";

#[test]
fn accept_recovers_after_fd_exhaustion() {
    let exe = env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .env(CHILD_SENTINEL, "1")
        .arg("--test-threads=1")
        .arg("accept_fd_exhaustion_child")
        .output()
        .expect("spawn child");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child failed (exit {}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status,
    );
}

#[test]
fn accept_fd_exhaustion_child() {
    if env::var(CHILD_SENTINEL).is_err() {
        return;
    }

    let limit = libc::rlimit {
        rlim_cur: 32,
        rlim_max: 32,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();

    // Place a connection in the kernel backlog before exhausting FDs.
    let backlog_conn = std::net::TcpStream::connect(addr).expect("backlog connect");

    // Exhaust remaining FDs.
    let mut held_fds = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => held_fds.push(f),
            Err(_) => break,
        }
    }

    // accept() should fail with EMFILE: there's a connection in the
    // backlog but no FD available for the accepted socket.
    let first = listener.accept();
    match first {
        Err(ref e) if e.raw_os_error() == Some(libc::EMFILE) => {}
        Err(ref e) => panic!("expected EMFILE, got: {e}"),
        Ok(_) => {
            // OS found a spare slot — skip gracefully.
            return;
        }
    }

    // Release FDs.
    held_fds.clear();
    drop(backlog_conn);

    // Make a fresh connection now that FDs are available.
    let client = std::net::TcpStream::connect(addr).expect("connect after FD release");

    // Retry: accept should now succeed, proving that an accept loop
    // retrying on EMFILE (like the proxy does) will recover once FDs
    // are available again.
    let (accepted, _peer) = listener
        .accept()
        .expect("accept should succeed after FD release");

    // Verify the connection is functional.
    (&client).write_all(b"ping").expect("write");
    let mut buf = [0u8; 4];
    (&accepted).read_exact(&mut buf).expect("read");
    assert_eq!(&buf, b"ping");
}
