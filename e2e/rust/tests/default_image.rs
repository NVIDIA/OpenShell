// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for the default NVIDIA Ubuntu workload image.

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

#[tokio::test]
async fn sandbox_from_default_image() {
    let mut guard = SandboxGuard::create_with_gateway_default(&["--", "cat", "/etc/os-release"])
        .await
        .expect("sandbox create from default image");

    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains("ID=ubuntu"),
        "expected Ubuntu OS release info in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}

#[tokio::test]
async fn sandbox_from_explicit_nvidia_ubuntu_image() {
    let image = "nvcr.io/nvidia/base/ubuntu:24.04";
    let mut guard = SandboxGuard::create(&["--from", image, "--", "cat", "/etc/os-release"])
        .await
        .expect("sandbox create from explicit NVIDIA Ubuntu image");

    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains("ID=ubuntu"),
        "expected Ubuntu OS release info in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}
