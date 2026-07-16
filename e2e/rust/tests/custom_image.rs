// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: build a custom container image and run a sandbox with it.
//!
//! Prerequisites:
//! - A running Docker- or Podman-backed OpenShell gateway
//! - Docker or Podman runtime running (for image build)
//! - The `openshell` binary (built automatically from the workspace)

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const MARKER: &str = "userless-image-e2e-marker";

fn assert_userless_output(output: &str) {
    let lines = output.lines().map(str::trim).collect::<Vec<_>>();
    assert!(
        lines.contains(&MARKER),
        "expected marker '{MARKER}' in sandbox output:\n{output}"
    );
    assert!(
        lines.iter().filter(|line| **line == "10001").count() >= 2,
        "expected UID and GID 10001:\n{output}"
    );
    assert!(
        lines.contains(&"/sandbox"),
        "expected sandbox home:\n{output}"
    );
}

#[cfg(all(feature = "e2e-podman", not(feature = "e2e-docker")))]
async fn assert_userless_image(image: &str) {
    let mut guard = SandboxGuard::create(&[
        "--from",
        image,
        "--",
        "sh",
        "-lc",
        "cat /etc/marker.txt; id -u; id -g; printf \"%s\\n\" \"$HOME\"; touch \"$HOME/userless-e2e\"",
    ])
    .await
    .expect("sandbox create from userless image");

    let clean_output = strip_ansi(&guard.create_output);
    assert_userless_output(&clean_output);
    guard.cleanup().await;
}

/// Docker's local Dockerfile builder provides the image directly to a Docker
/// gateway, so this path uses the CLI's standard `--from Dockerfile` flow.
#[cfg(feature = "e2e-docker")]
#[tokio::test]
async fn docker_sandbox_from_userless_dockerfile() {
    let dockerfile_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/userless/Dockerfile");
    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");
    let mut guard = SandboxGuard::create(&[
        "--from",
        dockerfile_str,
        "--",
        "sh",
        "-lc",
        "cat /etc/marker.txt; id -u; id -g; printf \"%s\\n\" \"$HOME\"; touch \"$HOME/userless-e2e\"",
    ])
    .await
    .expect("sandbox create from Dockerfile");

    let clean_output = strip_ansi(&guard.create_output);
    assert_userless_output(&clean_output);

    // Explicit cleanup (also happens in Drop, but explicit is clearer in tests).
    guard.cleanup().await;
}

/// Podman has its own local image store, so build the shared fixture with the
/// selected engine instead of relying on Docker's `--from Dockerfile` path.
#[cfg(all(feature = "e2e-podman", not(feature = "e2e-docker")))]
#[tokio::test]
async fn podman_sandbox_from_userless_image() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/userless");
    let image = format!("openshell/e2e-userless:{}", std::process::id());
    let status = tokio::process::Command::new("podman")
        .args([
            "build",
            "--tag",
            &image,
            fixture.to_str().expect("fixture path is UTF-8"),
        ])
        .status()
        .await
        .expect("run podman build");
    assert!(status.success(), "build userless fixture with podman");

    assert_userless_image(&image).await;

    let _ = tokio::process::Command::new("podman")
        .args(["image", "rm", "--force", &image])
        .status()
        .await;
}
