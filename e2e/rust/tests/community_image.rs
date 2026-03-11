// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: pull and launch a community sandbox image from GHCR.
//!
//! This test verifies that:
//! 1. The `base` community sandbox image can be pulled from GHCR
//! 2. A sandbox can be created and run using the community image
//! 3. Basic command execution works inside the community sandbox
//!
//! Prerequisites:
//! - A running openshell gateway (`openshell gateway start`)
//! - Network access to ghcr.io/nvidia/openshell-community/sandboxes/

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

/// Create a sandbox using the community `base` image and verify it works.
///
/// The `--from base` argument should resolve to:
/// `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`
#[tokio::test]
async fn sandbox_from_community_base_image() {
    // Create a sandbox using the community "base" image.
    // The CLI should expand "base" to the full GHCR path.
    let mut guard = SandboxGuard::create(&["--from", "base", "--", "echo", "community-image-ok"])
        .await
        .expect("sandbox create from community base image");

    // Verify the command output contains our marker.
    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains("community-image-ok"),
        "expected 'community-image-ok' in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}

/// Create a sandbox using the full GHCR image path explicitly.
///
/// This tests that explicit image references work correctly.
#[tokio::test]
async fn sandbox_from_explicit_ghcr_image() {
    let image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";

    let mut guard = SandboxGuard::create(&["--from", image, "--", "cat", "/etc/os-release"])
        .await
        .expect("sandbox create from explicit GHCR image");

    // The base image should have an /etc/os-release file.
    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains("ID=") || clean_output.contains("NAME="),
        "expected OS release info in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}
