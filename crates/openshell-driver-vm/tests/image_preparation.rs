// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "compute-driver")]
#![allow(unsafe_code)]

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use openshell_driver_vm::VmDriverConfig;

/// Exercise the actual worker entry point and a real sparse-file copy without
/// downloading an image, running a VM, or requiring host filesystem utilities.
#[test]
fn worker_publishes_complete_overlay_and_reports_resolved_owner() {
    worker_overlay_case(false);
}

/// Retrying an interrupted first start must never turn an incomplete copy
/// into persisted overlay state. The next retry must still be able to start.
#[test]
fn interrupted_missing_overlay_retry_does_not_publish_partial_state() {
    worker_overlay_case(true);
}

fn worker_overlay_case(interrupt_retry: bool) {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("images");
    let attempts = cache.join("preparations");
    let name = "attempt-00000000000000000000000000000001";
    let attempt = attempts.join(name);
    fs::create_dir_all(&attempt).unwrap();
    let lease_path = attempts.join(format!("{name}.lease"));
    fs::write(&lease_path, b"openshell-image-preparation-v1\n").unwrap();
    let lease = File::open(&lease_path).unwrap();
    let fd = lease.as_raw_fd();
    // SAFETY: this descriptor belongs to the live fixture file.
    assert_eq!(unsafe { libc::flock(fd, libc::LOCK_EX) }, 0);

    let size = 1024 * 1024;
    let template = cache.join("overlay-templates/sandbox-overlay-ext4-v1/1048576.ext4");
    fs::create_dir_all(template.parent().unwrap()).unwrap();
    let mut expected = vec![0_u8; size];
    expected[..13].copy_from_slice(b"template-data");
    fs::write(&template, &expected).unwrap();
    let sandbox = root.path().join("sandboxes/worker-test");
    fs::create_dir_all(&sandbox).unwrap();
    if interrupt_retry {
        // A cancelled Fresh attempt can persist the owner before publishing
        // its first overlay. Start retries this state with PreserveExisting.
        fs::write(
            sandbox.join("sandbox-owner-state"),
            b"sandbox-owner-v2:1000:1000\n",
        )
        .unwrap();
    }
    let source = cache.join("test-image/rootfs.ext4");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"identity comes from driver configuration").unwrap();
    let config = VmDriverConfig {
        state_dir: root.path().to_path_buf(),
        sandbox_uid: Some(1000),
        sandbox_gid: Some(1000),
        overlay_disk_mib: 1,
        ..VmDriverConfig::default()
    };
    let request = attempt.join("request.json");
    fs::write(
        &request,
        serde_json::to_vec(&serde_json::json!({
            "config": config,
            "sandbox_id": "worker-test",
            "image_ref": "",
            "rootfs_tar": null,
            "bootstrap_only": false,
            "overlay": {
                "source_disk": source,
                "preparation": if interrupt_retry { "PreserveExisting" } else { "Fresh" },
            },
            "lease_fd": fd,
            "parent_pid": std::process::id(),
        }))
        .unwrap(),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell-driver-vm"));
    command
        .arg("--internal-prepare-image")
        .arg(&request)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: only fcntl runs between fork and exec, and the fixture keeps its
    // descriptor alive until the worker has exited.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if interrupt_retry {
        let tools = root.path().join("tools");
        fs::create_dir(&tools).unwrap();
        let copy_ready = root.path().join("copy-ready");
        let cp = tools.join("cp");
        // Control only the external copy command. The actual worker selects
        // the destination and executes its production preservation checks.
        fs::write(
            &cp,
            "#!/bin/sh\nfor argument in \"$@\"; do destination=\"$argument\"; done\nprintf partial > \"$destination\"\nprintf '%s' \"$destination\" > \"$COPY_READY\"\nsleep 300\n",
        )
        .unwrap();
        fs::set_permissions(&cp, fs::Permissions::from_mode(0o700)).unwrap();
        command
            .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
            .env("COPY_READY", &copy_ready);
        let mut interrupted = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !copy_ready.exists() && std::time::Instant::now() < deadline {
            if interrupted.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Kill and reap even if readiness fails, so failed tests do not leave
        // a blocked helper or worker behind.
        if interrupted.try_wait().unwrap().is_none() {
            let pid = i32::try_from(interrupted.id()).unwrap();
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        interrupted.wait().unwrap();
        assert!(copy_ready.exists(), "worker must reach the controlled copy");
        assert!(
            !sandbox.join("overlay.ext4").exists(),
            "interrupted retry must leave no partial persisted overlay"
        );
        let destination = fs::read_to_string(&copy_ready).unwrap();
        assert!(std::path::Path::new(&destination).starts_with(&attempt));
        // Retry using the real copy utility. The incomplete attempt image
        // must not prevent publishing the complete overlay.
        command
            .env("PATH", "/usr/bin:/bin")
            .env_remove("COPY_READY");
    }
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let pid = i32::try_from(child.id()).unwrap();
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = child.wait();
            panic!("image preparation worker timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = String::from_utf8(output.stdout).unwrap();
    let completion = messages
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("worker stdout must contain only protocol messages")
        })
        .find_map(|message| message.get("Complete").cloned())
        .expect("worker completion");
    assert_eq!(
        completion,
        serde_json::json!({"Ok": {"Overlay": {"uid": 1000, "gid": 1000}}})
    );
    assert_eq!(fs::read(sandbox.join("overlay.ext4")).unwrap(), expected);
    assert_eq!(
        fs::read(&template).unwrap(),
        expected,
        "the shared template is immutable"
    );
    assert_eq!(
        fs::read_to_string(sandbox.join("sandbox-owner-state")).unwrap(),
        "sandbox-owner-v2:1000:1000\n"
    );
}
