// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! Docker GPU e2e test.
//!
//! Requires a Docker-backed gateway started with Docker CDI support. The
//! `e2e:docker:gpu` mise task starts that gateway with the default sandbox image
//! unless OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE is set.

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

#[tokio::test]
async fn docker_gpu_sandbox_runs_nvidia_smi() {
    let mut guard = SandboxGuard::create(&[
        "--gpu",
        "--",
        "sh",
        "-lc",
        "gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n 1); \
         test -n \"$gpu_name\"; \
         printf 'gpu-ok:%s\n' \"$gpu_name\"",
    ])
    .await
    .expect("GPU sandbox create should succeed");

    let output = strip_ansi(&guard.create_output);
    assert!(
        output.contains("gpu-ok:"),
        "expected GPU smoke marker in sandbox output:\n{output}"
    );

    guard.cleanup().await;
}
