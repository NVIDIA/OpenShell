// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! CDI GPU e2e tests.
//!
//! Requires a CDI-enabled gateway backed by Docker or Podman. The
//! `e2e:docker:gpu` and `e2e:podman:gpu` mise tasks start the corresponding
//! gateway with the default sandbox image unless the task-specific sandbox
//! image environment variable is set.

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

async fn assert_nvidia_smi(args: &[&str]) {
    let mut create_args = Vec::from(args);
    create_args.extend([
        "--",
        "sh",
        "-lc",
        "gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n 1); \
         test -n \"$gpu_name\"; \
         printf 'gpu-ok:%s\\n' \"$gpu_name\"",
    ]);

    let mut guard = SandboxGuard::create(&create_args)
        .await
        .expect("GPU sandbox create should succeed");

    let output = strip_ansi(&guard.create_output);
    assert!(
        output.contains("gpu-ok:"),
        "expected GPU smoke marker in sandbox output:\n{output}"
    );

    guard.cleanup().await;
}

#[tokio::test]
async fn cdi_gpu_sandbox_runs_nvidia_smi() {
    assert_nvidia_smi(&["--gpu"]).await;
}

#[tokio::test]
async fn cdi_gpu_sandbox_runs_nvidia_smi_with_specific_device() {
    assert_nvidia_smi(&["--gpu", "--gpu-device", "nvidia.com/gpu=0"]).await;
}
