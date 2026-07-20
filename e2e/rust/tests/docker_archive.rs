// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: load a Docker archive (.tar) and run a sandbox with it.
//!
//! Prerequisites:
//! - A running Docker-backed openshell gateway (`mise run gateway:docker`)
//! - Docker daemon running (for image build + save)
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

RUN echo "docker-archive-e2e-marker" > /etc/marker.txt

CMD ["sleep", "infinity"]
"#;

const MARKER: &str = "docker-archive-e2e-marker";

/// Build a Docker image, export it as a .tar archive, then create a sandbox
/// from that archive and verify it contains the expected marker file.
#[tokio::test]
async fn sandbox_from_docker_archive() {
    let engine = ContainerEngine::from_env().expect("container engine available");
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    // Step 1: Write a Dockerfile and build an image.
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    std::fs::write(&dockerfile_path, DOCKERFILE_CONTENT).expect("write Dockerfile");

    let tag = format!(
        "openshell/e2e-archive-test:{}",
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

    // Step 2: Export the image to a .tar archive.
    let archive_path = tmpdir.path().join("image.tar");
    let save_output = engine
        .command()
        .args(["save", "-o"])
        .arg(&archive_path)
        .arg(&tag)
        .output()
        .expect("spawn docker save");

    assert!(
        save_output.status.success(),
        "docker save failed:\n{}",
        String::from_utf8_lossy(&save_output.stderr)
    );

    // Step 3: Remove the local image so the sandbox must load from the archive.
    let _ = engine.command().args(["rmi", &tag]).output();

    // Step 4: Create a sandbox from the Docker archive.
    let archive_str = archive_path.to_str().expect("archive path is UTF-8");
    let mut guard = SandboxGuard::create(&["--from", archive_str, "--", "cat", "/etc/marker.txt"])
        .await
        .expect("sandbox create from Docker archive");

    // Step 5: Verify the marker file content appears in the output.
    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains(MARKER),
        "expected marker '{MARKER}' in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}
