// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM driver host bind mounts over virtiofs: a read-write share round-trips
//! data with the host and a read-only share rejects writes.
//!
//! The sandbox overwrites a host-seeded file rather than creating one: on
//! Linux, libkrun running as a non-root user refuses file creation by a guest
//! user whose UID/GID differ from its own.
//!
//! Needs the libkrun backend (macOS HVF or Linux KVM); QEMU rejects virtiofs
//! mounts. The e2e VM gateway configures no GPU or QEMU-only lifecycle
//! extension, so this non-GPU sandbox always launches on libkrun.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use openshell_e2e::harness::sandbox::SandboxGuard;

const RW_TARGET: &str = "/sandbox/e2e-bind";
const RO_TARGET: &str = "/sandbox/e2e-bind-ro";

fn shared_host_dir(prefix: &str) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("create bind mount host dir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777))
        .expect("make bind mount host dir writable by sandbox user");
    let input = dir.path().join("input.txt");
    fs::write(&input, "host-bind-ok").expect("seed bind mount host dir");
    fs::set_permissions(&input, fs::Permissions::from_mode(0o666))
        .expect("make bind mount input readable by sandbox user");
    dir
}

fn seed_world_writable(path: &std::path::Path) {
    fs::write(path, "").expect("seed bind mount output file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))
        .expect("make bind mount output writable by sandbox user");
}

#[tokio::test]
async fn vm_bind_mount() {
    let rw_dir = shared_host_dir("openshell-e2e-vm-bind-rw-");
    let ro_dir = shared_host_dir("openshell-e2e-vm-bind-ro-");
    seed_world_writable(&rw_dir.path().join("output.txt"));

    // `type: bind` keeps the entry identical to Docker/Podman bind mounts.
    let driver_config = serde_json::json!({
        "vm": {
            "mounts": [
                {
                    "type": "bind",
                    "source": rw_dir.path(),
                    "target": RW_TARGET,
                    "read_only": false
                },
                {
                    "source": ro_dir.path(),
                    "target": RO_TARGET
                }
            ]
        }
    })
    .to_string();

    let script = format!(
        "set -eu; \
         test \"$(cat {RW_TARGET}/input.txt)\" = host-bind-ok; \
         test \"$(cat {RO_TARGET}/input.txt)\" = host-bind-ok; \
         printf sandbox-bind-ok > {RW_TARGET}/output.txt; \
         if printf x > {RO_TARGET}/input.txt 2>/dev/null; then echo ro-writable; exit 1; fi; \
         echo vm-bind-ok"
    );
    let mut sandbox = SandboxGuard::create(&[
        "--driver-config-json",
        &driver_config,
        "--",
        "sh",
        "-lc",
        &script,
    ])
    .await
    .expect("sandbox create with VM bind mounts");

    assert!(
        sandbox.create_output.contains("vm-bind-ok"),
        "sandbox should read both shares, write the rw share, and be denied on the ro share:\n{}",
        sandbox.create_output
    );

    sandbox.cleanup().await;
    let output = fs::read_to_string(rw_dir.path().join("output.txt"))
        .expect("read sandbox output from rw host dir");
    assert_eq!(output, "sandbox-bind-ok");
    // Overwriting an existing world-writable file is the write libkrun would
    // otherwise allow, so only the read-only share can be what refuses it.
    let ro_input =
        fs::read_to_string(ro_dir.path().join("input.txt")).expect("read input from ro host dir");
    assert_eq!(
        ro_input, "host-bind-ok",
        "read-only share must not receive writes"
    );
}
