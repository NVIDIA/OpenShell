// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end integration test against a real, system-provided `containerd`.
//!
//! This is intentionally `#[ignore]`d: it requires a reachable `containerd`
//! socket, `runc` (or the configured `runtime_binary`) installed, network
//! privileges (`CAP_NET_ADMIN`, to create a network namespace and veth
//! pair), and outbound network access to pull `docker.io/library/busybox`.
//! None of that is available in the default CI environment, so this is a
//! developer/maintainer-run verification, not part of the automated suite.
//!
//! Run it explicitly, with root (needed for `ip netns add`/veth creation)
//! and preserving the environment so `cargo` stays on `$PATH`:
//!
//! ```sh
//! sudo -E $(which cargo) test -p openshell-driver-oci --test containerd_integration -- --ignored --nocapture
//! ```
//!
//! This exact flow was verified manually against a real `containerd` 2.x
//! plus `runc`/`crun` install during development: pull, then chain-ID
//! resolve, then snapshot prepare (protected by a containerd lease), then
//! a bundle mounted and driven directly through `runc`/`crun`'s own
//! `create`/`start`/`state`/`delete` CLI contract (containerd's
//! `Containers`/`Tasks` services are never used — see `driver.rs`'s module
//! doc comment), plus joining a driver-managed network namespace.
//!
//! This test automates that same verification for future contributors and
//! CI environments that do have containerd available (e.g. a future
//! dedicated oci-driver E2E lane, tracked alongside `mise run e2e:vm`
//! and `mise run e2e:docker`).

use openshell_core::proto::compute::v1::{DriverSandbox, DriverSandboxSpec, DriverSandboxTemplate};
use openshell_driver_oci::{OciComputeConfig, OciComputeDriver};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

const TEST_IMAGE: &str = "docker.io/library/busybox:latest";

async fn containerd_reachable(socket_path: &std::path::Path) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        openshell_rootfs::ContainerdRootfsProvider::connect(
            socket_path,
            "openshell-test",
            "overlayfs",
        ),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

/// Write a minimal "supervisor" shell script that just sleeps, standing in
/// for the real `openshell-sandbox` binary (not built as part of this
/// crate's test fixtures). Proves the bind-mount + entrypoint-override path
/// works without depending on the real supervisor.
fn write_fake_supervisor(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("fake-supervisor.sh");
    let mut file = std::fs::File::create(&path).expect("create fake supervisor script");
    file.write_all(b"#!/bin/sh\nsleep 60\n")
        .expect("write fake supervisor script");
    let mut perms = file.metadata().expect("script metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod fake supervisor script");
    path
}

#[tokio::test]
#[ignore = "requires a reachable system containerd, runc, and CAP_NET_ADMIN; see module docs"]
async fn create_get_stop_delete_sandbox_round_trip() {
    run_round_trip("runc").await;
}

#[tokio::test]
#[ignore = "requires a reachable system containerd, crun, and CAP_NET_ADMIN; see module docs"]
async fn create_get_stop_delete_sandbox_round_trip_with_crun() {
    // Proves the configurable-low-level-runtime design point end to end:
    // this driver never bundles or hardcodes a runtime, and containerd is
    // not involved in selecting or invoking it at all (unlike an earlier
    // revision of this driver, which went through containerd's shim) --
    // swapping `runtime_binary` is the entire story.
    run_round_trip("crun").await;
}

async fn run_round_trip(runtime_binary: &str) {
    let socket_path = OciComputeConfig::default().containerd_socket_path;
    if !containerd_reachable(&socket_path).await {
        eprintln!(
            "skipping: containerd not reachable at {} (this test requires a real containerd install)",
            socket_path.display()
        );
        return;
    }

    let state_dir = tempfile::tempdir().expect("tempdir for state_dir");
    let supervisor_path = write_fake_supervisor(state_dir.path());

    let config = OciComputeConfig {
        default_image: TEST_IMAGE.to_string(),
        state_dir: state_dir.path().to_path_buf(),
        supervisor_binary_path: Some(supervisor_path),
        containerd_namespace: "openshell-test".to_string(),
        runtime_binary: runtime_binary.to_string(),
        // `rootless` defaults to `false`; see `OciComputeConfig::rootless`
        // for the known containerd-snapshot-ownership gap that currently
        // makes `rootless: true` fail container start.
        ..OciComputeConfig::default()
    };

    let driver = OciComputeDriver::new(config)
        .await
        .expect("driver connects to containerd");

    let sandbox_id = format!(
        "it-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let sandbox_name = sandbox_id.clone();
    let sandbox = DriverSandbox {
        id: sandbox_id.clone(),
        name: sandbox_name.clone(),
        namespace: String::new(),
        spec: Some(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                image: TEST_IMAGE.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
        workspace: String::new(),
    };

    driver
        .validate_sandbox_create(&sandbox)
        .expect("sandbox request validates");

    driver
        .create_sandbox(&sandbox)
        .await
        .expect("create_sandbox succeeds against real containerd");

    // Give the task a moment to reach Running before observing it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let observed = driver
        .get_sandbox(&sandbox_name)
        .expect("get_sandbox does not error")
        .expect("sandbox exists after create");
    let status = observed.status.expect("status present");
    assert!(
        status
            .conditions
            .iter()
            .any(|c| c.r#type == "Ready" && c.status == "True"),
        "expected a Ready=True condition, got {:?}",
        status.conditions
    );

    let listed = driver
        .list_sandboxes()
        .expect("list_sandboxes does not error");
    assert!(
        listed.iter().any(|s| s.id == sandbox_id),
        "created sandbox should appear in list_sandboxes"
    );

    driver
        .stop_sandbox(&sandbox_name)
        .await
        .expect("stop_sandbox succeeds");

    let deleted = driver
        .delete_sandbox(&sandbox_id, &sandbox_name)
        .await
        .expect("delete_sandbox succeeds");
    assert!(
        deleted,
        "delete_sandbox should report a resource was deleted"
    );

    let gone = driver
        .get_sandbox(&sandbox_name)
        .expect("get_sandbox does not error after delete");
    assert!(
        gone.is_none(),
        "sandbox should no longer exist after delete"
    );
}
