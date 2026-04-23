// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Non-GPU boot smoke tests for the QEMU backend.
//!
//! Boots a VM **without** VFIO/GPU passthrough and verifies the kernel boots
//! and init runs. This catches backend regressions on regular CI runners
//! that lack GPU hardware.
//!
//! Gated on `OPENSHELL_VM_BACKEND` — set to `qemu` to run the tests.
//! Skipped when the env var is absent.
//!
//! Requires the VM runtime bundle (vmlinux, virtiofsd, rootfs, and the
//! backend binary) to be installed. Set `OPENSHELL_VM_RUNTIME_DIR` or run
//! `mise run vm:bundle-runtime` first.
//!
//! Run explicitly:
//!
//! ```sh
//! OPENSHELL_VM_BACKEND=qemu cargo test -p openshell-vm --test vm_boot_smoke
//! ```

#![allow(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::Duration;

const GATEWAY: &str = env!("CARGO_BIN_EXE_openshell-vm");

fn runtime_bundle_dir() -> std::path::PathBuf {
    std::path::Path::new(GATEWAY)
        .parent()
        .expect("openshell-vm binary has no parent")
        .join("openshell-vm.runtime")
}

fn require_bundle() {
    let bundle = runtime_bundle_dir();
    if !bundle.is_dir() {
        panic!(
            "VM runtime bundle not found at {}. Run `mise run vm:bundle-runtime` first.",
            bundle.display()
        );
    }
}

fn skip_unless_qemu() -> bool {
    if std::env::var("OPENSHELL_VM_BACKEND").as_deref() != Ok("qemu") {
        eprintln!("OPENSHELL_VM_BACKEND != qemu — skipping");
        return true;
    }
    false
}

#[test]
fn qemu_exec_exits_cleanly() {
    if skip_unless_qemu() {
        return;
    }
    require_bundle();

    let mut child = Command::new(GATEWAY)
        .args(["--backend", "qemu", "--net", "none", "--exec", "/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start openshell-vm");

    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "qemu --exec /bin/true exited with {status}"
                );
                return;
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
                    let _ = child.wait();
                    panic!("QEMU VM did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => panic!("error waiting for openshell-vm: {e}"),
        }
    }
}

#[test]
fn qemu_boots_without_gpu() {
    if skip_unless_qemu() {
        return;
    }
    require_bundle();

    if !nix_is_root() {
        eprintln!("skipping full gateway boot — requires root for TAP networking");
        return;
    }

    let mut child = Command::new(GATEWAY)
        .args(["--backend", "qemu"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start openshell-vm");

    let addr: std::net::SocketAddr = ([127, 0, 0, 1], 30051).into();
    let timeout = Duration::from_secs(180);
    let start = std::time::Instant::now();
    let mut reachable = false;

    while start.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
            reachable = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = child.wait();

    assert!(
        reachable,
        "QEMU VM service on port 30051 not reachable within {timeout:?}"
    );
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
