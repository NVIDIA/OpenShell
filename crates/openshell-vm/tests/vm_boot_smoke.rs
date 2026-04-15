// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Non-GPU cloud-hypervisor boot smoke test.
//!
//! Boots a cloud-hypervisor VM **without** VFIO/GPU passthrough and verifies
//! the kernel boots and init runs. This catches backend regressions on regular
//! CI runners that lack GPU hardware.
//!
//! Gated on `OPENSHELL_VM_BACKEND=cloud-hypervisor` — skipped when the env
//! var is absent or set to a different backend.
//!
//! Requires the VM runtime bundle (cloud-hypervisor, vmlinux, virtiofsd,
//! rootfs) to be installed. Set `OPENSHELL_VM_RUNTIME_DIR` or run
//! `mise run vm:bundle-runtime` first.
//!
//! Run explicitly:
//!
//! ```sh
//! OPENSHELL_VM_BACKEND=cloud-hypervisor cargo test -p openshell-vm --test vm_boot_smoke
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

fn skip_unless_chv() -> bool {
    if std::env::var("OPENSHELL_VM_BACKEND").as_deref() != Ok("cloud-hypervisor") {
        eprintln!("OPENSHELL_VM_BACKEND != cloud-hypervisor — skipping");
        return true;
    }
    false
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

#[test]
fn cloud_hypervisor_exec_exits_cleanly() {
    if skip_unless_chv() {
        return;
    }
    require_bundle();

    // Boot with --exec /bin/true --net none. The cloud-hypervisor backend
    // wraps the exec command in a script that calls `poweroff -f` after
    // completion, causing a clean ACPI shutdown.
    let mut child = Command::new(GATEWAY)
        .args([
            "--backend",
            "cloud-hypervisor",
            "--net",
            "none",
            "--exec",
            "/bin/true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start openshell-vm");

    // The VM should boot, run /bin/true, and exit within ~5s.
    // Give 30s for slow CI.
    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "cloud-hypervisor --exec /bin/true exited with {status}"
                );
                return;
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
                    let _ = child.wait();
                    panic!("cloud-hypervisor VM did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => panic!("error waiting for openshell-vm: {e}"),
        }
    }
}

#[test]
fn cloud_hypervisor_boots_without_gpu() {
    if skip_unless_chv() {
        return;
    }
    require_bundle();

    // Full gateway boot requires TAP networking (root/CAP_NET_ADMIN).
    // Skip unless running as root.
    if !nix_is_root() {
        eprintln!("skipping full gateway boot — requires root for TAP networking");
        return;
    }

    let mut child = Command::new(GATEWAY)
        .args(["--backend", "cloud-hypervisor"])
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
        "cloud-hypervisor VM service on port 30051 not reachable within {timeout:?}"
    );
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
