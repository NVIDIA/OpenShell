// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests: create a sandbox from a flat rootfs tar archive, plain and
//! gzip-compressed.
//!
//! Prerequisites:
//! - A running VM-backed openshell gateway with a default sandbox image configured
//! - Docker daemon running (for image build + container export)
//! - The `openshell` binary (built automatically from the workspace)

use openshell_e2e::harness::container::ContainerEngine;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Build a Docker image and export its filesystem as a flat rootfs tar.
///
/// `suffix` keeps the image tag and temporary container name unique so tests
/// exercising different archive formats can run concurrently.
fn export_rootfs_tar(engine: &ContainerEngine, tmpdir: &Path, suffix: &str) -> PathBuf {
    let dockerfile_path = tmpdir.join("Dockerfile");
    std::fs::write(&dockerfile_path, DOCKERFILE_CONTENT).expect("write Dockerfile");

    let tag = format!(
        "openshell/e2e-rootfs-tar-test-{suffix}:{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    let build_output = engine
        .command()
        .args(["build", "-t", &tag, "-f"])
        .arg(&dockerfile_path)
        .arg(tmpdir)
        .output()
        .expect("spawn docker build");

    assert!(
        build_output.status.success(),
        "docker build failed:\n{}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    // Create a temporary container and export its filesystem as a flat rootfs
    // tar (equivalent to `docker export`).
    let container_name = format!(
        "openshell-e2e-rootfs-export-{suffix}-{}",
        std::process::id()
    );

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

    let rootfs_tar_path = tmpdir.join("rootfs.tar");
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

    rootfs_tar_path
}

/// Create a sandbox from `archive` and assert the marker baked into the image
/// shows up in its output.
async fn assert_sandbox_from_archive(archive: &Path) {
    let archive_str = archive.to_str().expect("archive path is UTF-8");
    let mut guard = SandboxGuard::create(&["--from", archive_str, "--", "cat", "/etc/marker.txt"])
        .await
        .expect("sandbox create from rootfs tar");

    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains(MARKER),
        "expected marker '{MARKER}' in sandbox output for {}:\n{clean_output}",
        archive.display()
    );

    guard.cleanup().await;
}

/// Build a Docker image, export its filesystem as a flat rootfs tar, then
/// create a sandbox from that tar and verify it contains the expected marker.
#[tokio::test]
async fn sandbox_from_rootfs_tar() {
    let engine = ContainerEngine::from_env().expect("container engine available");
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    let rootfs_tar_path = export_rootfs_tar(&engine, tmpdir.path(), "plain");

    assert_sandbox_from_archive(&rootfs_tar_path).await;
}

/// The CLI advertises `.tar.gz` and `.tgz` sources, so a gzip-compressed
/// export has to reach the sandbox the same way a plain tar does.
#[tokio::test]
async fn sandbox_from_gzipped_rootfs_tar() {
    let engine = ContainerEngine::from_env().expect("container engine available");
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    let rootfs_tar_path = export_rootfs_tar(&engine, tmpdir.path(), "gzip");
    let gzipped_path = tmpdir.path().join("rootfs.tar.gz");
    let gzipped = std::fs::File::create(&gzipped_path).expect("create gzip archive");
    let gzip_status = Command::new("gzip")
        .arg("-c")
        .arg(&rootfs_tar_path)
        .stdout(gzipped)
        .status()
        .expect("spawn gzip");
    assert!(gzip_status.success(), "gzip failed: {gzip_status}");
    std::fs::remove_file(&rootfs_tar_path).expect("remove uncompressed archive");

    assert_sandbox_from_archive(&gzipped_path).await;
}
