// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GPU workload validation e2e tests.

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const CUDA_WORKLOAD_IMAGE_ENV: &str = "OPENSHELL_E2E_GPU_CUDA_WORKLOAD_IMAGE";
const GPU_WORKLOAD_SUCCESS_MARKER: &str = "OPENSHELL_GPU_WORKLOAD_SUCCESS";

fn cuda_workload_image() -> Option<String> {
    std::env::var(CUDA_WORKLOAD_IMAGE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[tokio::test]
async fn cuda_gpu_workload_validation_runs_with_default_image_command() {
    let Some(image) = cuda_workload_image() else {
        eprintln!("skipping CUDA GPU workload validation: {CUDA_WORKLOAD_IMAGE_ENV} is not set");
        return;
    };

    let mut guard = SandboxGuard::create(&["--gpu", "--from", image.as_str()])
        .await
        .unwrap_or_else(|err| {
            panic!("CUDA GPU workload sandbox create failed for image {image}:\n{err}")
        });

    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains(GPU_WORKLOAD_SUCCESS_MARKER),
        "expected success marker {GPU_WORKLOAD_SUCCESS_MARKER} for image {image} in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}
