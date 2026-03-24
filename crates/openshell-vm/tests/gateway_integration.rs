// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the standalone `gateway` binary.
//!
//! These tests require:
//! - libkrun installed (e.g. `brew tap slp/krun && brew install libkrun`)
//! - macOS ARM64 with Apple Hypervisor.framework
//! - A pre-built rootfs at `~/.local/share/nemoclaw/gateway/rootfs`
//!
//! All tests are `#[ignore]` — run them explicitly:
//!
//! ```sh
//! cargo test -p openshell-vm --test gateway_integration -- --ignored
//! ```

#![allow(unsafe_code)]

use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the built `gateway` binary (resolved by Cargo at compile time).
const GATEWAY: &str = env!("CARGO_BIN_EXE_gateway");

// ── Helpers ────────────────────────────────────────────────────────────

/// Codesign the binary on macOS so it can access Hypervisor.framework.
fn codesign_if_needed() {
    if cfg!(target_os = "macos") {
        let entitlements = format!("{}/entitlements.plist", env!("CARGO_MANIFEST_DIR"));
        let status = Command::new("codesign")
            .args([
                "--entitlements",
                &entitlements,
                "--force",
                "-s",
                "-",
                GATEWAY,
            ])
            .status()
            .expect("codesign command failed to execute");
        assert!(status.success(), "failed to codesign gateway binary");
    }
}

fn assert_runtime_bundle_staged() {
    let bundle_dir = std::path::Path::new(GATEWAY)
        .parent()
        .expect("gateway binary has no parent")
        .join("gateway.runtime");
    assert!(
        bundle_dir.is_dir(),
        "gateway.runtime is missing next to the test binary: {}. Run `mise run vm:bundle-runtime` first.",
        bundle_dir.display()
    );
}

// ── Tests ──────────────────────────────────────────────────────────────

/// Boot the full NemoClaw gateway and verify the gRPC service becomes
/// reachable on port 30051.
#[test]
#[ignore] // requires libkrun + rootfs
fn gateway_boots_and_service_becomes_reachable() {
    codesign_if_needed();
    assert_runtime_bundle_staged();

    let mut cmd = Command::new(GATEWAY);
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to start gateway");

    // Poll for the navigator gRPC service.
    let addr: SocketAddr = ([127, 0, 0, 1], 30051).into();
    let timeout = Duration::from_secs(180);
    let start = Instant::now();
    let mut reachable = false;

    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
            reachable = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    // Tear down regardless of result.
    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = child.wait();

    assert!(
        reachable,
        "gateway service on port 30051 not reachable within {timeout:?}"
    );
}

/// Run a trivial command inside the VM via `--exec` and verify it exits
/// successfully, proving the VM boots and can execute guest processes.
#[test]
#[ignore] // requires libkrun + rootfs
fn gateway_exec_runs_guest_command() {
    codesign_if_needed();
    assert_runtime_bundle_staged();

    let mut cmd = Command::new(GATEWAY);
    cmd.args(["--exec", "/bin/true"]);

    let output = cmd.output().expect("failed to run gateway --exec");

    assert!(
        output.status.success(),
        "gateway --exec /bin/true failed with status {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}
