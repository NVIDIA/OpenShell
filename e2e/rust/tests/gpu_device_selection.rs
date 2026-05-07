// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-gpu")]

//! GPU device selection e2e tests.
//!
//! Requires a GPU-backed gateway and a sandbox image containing `nvidia-smi`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::ContainerEngine;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::timeout;

const SANDBOX_CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const GPU_PROBE_DOCKERFILE_STAGE: &str = "gateway";

fn gpu_lines(output: &str) -> Vec<String> {
    strip_ansi(output)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("GPU "))
        .map(ToOwned::to_owned)
        .collect()
}

fn gpu_uuid(line: &str) -> &str {
    let (_, uuid) = line
        .rsplit_once("(UUID: ")
        .unwrap_or_else(|| panic!("GPU line did not include a UUID: {line}"));
    uuid.strip_suffix(')').unwrap_or(uuid)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("failed to resolve workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

fn dockerfile_images_gpu_probe_image() -> String {
    let dockerfile = workspace_root().join("deploy/docker/Dockerfile.images");
    let contents = std::fs::read_to_string(&dockerfile)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dockerfile.display()));

    contents
        .lines()
        .map(str::trim)
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let instruction = parts.next()?;
            let image = parts.next()?;
            let as_keyword = parts.next()?;
            let stage = parts.next()?;

            if instruction.eq_ignore_ascii_case("FROM")
                && as_keyword.eq_ignore_ascii_case("AS")
                && stage == GPU_PROBE_DOCKERFILE_STAGE
            {
                Some(image)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            panic!(
                "failed to find a FROM <image> AS {GPU_PROBE_DOCKERFILE_STAGE} stage in {}",
                dockerfile.display()
            )
        })
        .to_string()
}

fn gpu_probe_image() -> String {
    std::env::var("OPENSHELL_E2E_GPU_PROBE_IMAGE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(dockerfile_images_gpu_probe_image)
}

fn runtime_gpu_lines() -> Vec<String> {
    let engine = ContainerEngine::from_env();
    let image = gpu_probe_image();
    let output = engine
        .command()
        .args([
            "run",
            "--rm",
            "--device",
            "nvidia.com/gpu=all",
            image.as_str(),
            "nvidia-smi",
            "-L",
        ])
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to run {} GPU probe container with image {image}: {err}",
                engine.name()
            )
        });

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "{} GPU probe failed with image {image} and status {:?}:\n{}",
        engine.name(),
        output.status.code(),
        combined
    );

    let lines = gpu_lines(&stdout);
    assert!(
        !lines.is_empty(),
        "{} GPU probe did not report any GPU lines with image {image}:\n{combined}",
        engine.name()
    );
    lines
}

async fn sandbox_gpu_lines(gpu_device: Option<&str>) -> Vec<String> {
    let mut args = vec!["--gpu"];
    if let Some(gpu_device) = gpu_device {
        args.push("--gpu-device");
        args.push(gpu_device);
    }
    args.extend(["--", "sh", "-lc", "nvidia-smi -L"]);

    let mut guard = SandboxGuard::create(&args)
        .await
        .expect("GPU sandbox create should succeed");

    let lines = gpu_lines(&guard.create_output);
    guard.cleanup().await;
    lines
}

async fn sandbox_create_output(args: &[&str]) -> String {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox").arg("create").args(args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = timeout(SANDBOX_CREATE_TIMEOUT, cmd.output())
        .await
        .expect("sandbox create should complete before timeout")
        .expect("openshell command should spawn");

    assert!(
        !output.status.success(),
        "sandbox create unexpectedly succeeded with invalid GPU device"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    strip_ansi(&format!("{stdout}{stderr}"))
}

#[tokio::test]
async fn gpu_request_without_device_matches_plain_all_gpu_container() {
    let expected = runtime_gpu_lines();
    let actual = sandbox_gpu_lines(None).await;

    assert_eq!(
        actual, expected,
        "default GPU request should expose the same GPU lines as a plain all-GPU container"
    );
}

#[tokio::test]
async fn gpu_request_for_each_index_exposes_requested_gpu_uuid() {
    let expected = runtime_gpu_lines();

    for (index, expected_line) in expected.iter().enumerate() {
        let gpu_device = format!("nvidia.com/gpu={index}");
        let actual = sandbox_gpu_lines(Some(&gpu_device)).await;
        assert_eq!(
            actual.len(),
            1,
            "GPU request for {gpu_device} should expose one GPU line:\n{actual:#?}"
        );

        assert_eq!(
            gpu_uuid(&actual[0]),
            gpu_uuid(expected_line),
            "GPU request for {gpu_device} should expose the matching physical GPU UUID"
        );
    }
}

#[tokio::test]
async fn gpu_all_device_request_matches_plain_all_gpu_container() {
    let expected = runtime_gpu_lines();
    let actual = sandbox_gpu_lines(Some("nvidia.com/gpu=all")).await;

    assert_eq!(
        actual, expected,
        "explicit all-GPU request should expose the same GPU lines as a plain all-GPU container"
    );
}

#[tokio::test]
async fn gpu_invalid_device_request_fails() {
    let output = sandbox_create_output(&[
        "--gpu",
        "--gpu-device",
        "nvidia.com/gpu=invalid",
        "--",
        "sh",
        "-lc",
        "nvidia-smi -L",
    ])
    .await;
    let output_lower = output.to_ascii_lowercase();

    assert!(
        output.contains("nvidia.com/gpu=invalid")
            || output_lower.contains("cdi")
            || output_lower.contains("device"),
        "expected invalid GPU device failure to mention the requested device or CDI/device resolution:\n{output}"
    );
}
