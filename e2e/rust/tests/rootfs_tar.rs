// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: create a sandbox from a flat rootfs tar archive.
//!
//! Prerequisites:
//! - A running VM-backed openshell gateway with a default sandbox image configured
//! - Docker daemon running (for image build + container export)
//! - The `openshell` binary (built automatically from the workspace)

use openshell_e2e::harness::container::ContainerEngine;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const DOCKERFILE_CONTENT: &str = r#"FROM public.ecr.aws/docker/library/python:3.13-slim

# iproute2 is required for sandbox network namespace isolation.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create the sandbox user/group so the supervisor can switch to it.
RUN groupadd -g 1000660000 sandbox && \
    useradd -m -u 1000660000 -g sandbox sandbox

RUN echo "rootfs-tar-e2e-marker" > /etc/marker.txt

CMD ["sleep", "infinity"]
"#;

const MARKER: &str = "rootfs-tar-e2e-marker";

/// Build a Docker image, export its filesystem as a flat rootfs tar, then
/// create a sandbox from that tar and verify it contains the expected marker.
#[tokio::test]
async fn sandbox_from_rootfs_tar() {
    let engine = ContainerEngine::from_env().expect("container engine available");
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    // Step 1: Write a Dockerfile and build an image.
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    std::fs::write(&dockerfile_path, DOCKERFILE_CONTENT).expect("write Dockerfile");

    let tag = format!(
        "openshell/e2e-rootfs-tar-test:{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    let build_output = engine
        .command()
        .args(["build", "-t", &tag, "-f"])
        .arg(&dockerfile_path)
        .arg(tmpdir.path())
        .output()
        .expect("spawn docker build");

    assert!(
        build_output.status.success(),
        "docker build failed:\n{}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    // Step 2: Create a temporary container and export its filesystem as a
    // flat rootfs tar (equivalent to `docker export`).
    let container_name = format!("openshell-e2e-rootfs-export-{}", std::process::id());

    let create_output = engine
        .command()
        .args(["create", "--name", &container_name, &tag])
        .output()
        .expect("spawn docker create");

    assert!(
        create_output.status.success(),
        "docker create failed:\n{}",
        String::from_utf8_lossy(&create_output.stderr)
    );

    let rootfs_tar_path = tmpdir.path().join("rootfs.tar");
    let export_output = engine
        .command()
        .args(["export", "-o"])
        .arg(&rootfs_tar_path)
        .arg(&container_name)
        .output()
        .expect("spawn docker export");

    assert!(
        export_output.status.success(),
        "docker export failed:\n{}",
        String::from_utf8_lossy(&export_output.stderr)
    );

    // Clean up the temporary container and image.
    let _ = engine.command().args(["rm", &container_name]).output();
    let _ = engine.command().args(["rmi", &tag]).output();

    // Step 3: Create a sandbox from the rootfs tar.
    let tar_str = rootfs_tar_path.to_str().expect("tar path is UTF-8");
    let mut guard = SandboxGuard::create(&["--from", tar_str, "--", "cat", "/etc/marker.txt"])
        .await
        .expect("sandbox create from rootfs tar");

    // Step 4: Verify the marker file content appears in the output.
    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains(MARKER),
        "expected marker '{MARKER}' in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}
