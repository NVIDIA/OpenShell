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
use serde_json::{Map, Value};
use tokio::time::timeout;

const SANDBOX_CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const GPU_PROBE_DOCKERFILE_STAGE: &str = "gateway";
const CDI_GPU_DEVICE_ALL: &str = "nvidia.com/gpu=all";
const CDI_GPU_DEVICE_PREFIX: &str = "nvidia.com/gpu=";

fn gpu_lines(output: &str) -> Vec<String> {
    strip_ansi(output)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("GPU "))
        .map(ToOwned::to_owned)
        .collect()
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

fn object_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .or_else(|| object.get(&key.to_ascii_lowercase()))
        .and_then(Value::as_str)
}

fn discovered_devices_array(info: &Value) -> Option<&Vec<Value>> {
    info.get("DiscoveredDevices")
        .or_else(|| info.get("discoveredDevices"))
        .and_then(Value::as_array)
}

fn host_discovered_devices_array(info: &Value) -> Option<&Vec<Value>> {
    info.get("Host")
        .or_else(|| info.get("host"))
        .and_then(discovered_devices_array)
}

fn collect_cdi_gpu_device_ids_from_devices(devices: &[Value], device_ids: &mut Vec<String>) {
    for device in devices {
        let Some(device) = device.as_object() else {
            continue;
        };

        if object_string(device, "Source") == Some("cdi")
            && let Some(device_id) = object_string(device, "ID")
            && device_id.starts_with(CDI_GPU_DEVICE_PREFIX)
        {
            device_ids.push(device_id.to_string());
        }
    }
}

fn parse_cdi_gpu_device_ids(info: &Value) -> Vec<String> {
    let mut device_ids = Vec::new();

    if let Some(devices) = discovered_devices_array(info) {
        collect_cdi_gpu_device_ids_from_devices(devices, &mut device_ids);
    }
    if let Some(devices) = host_discovered_devices_array(info) {
        collect_cdi_gpu_device_ids_from_devices(devices, &mut device_ids);
    }

    device_ids.sort();
    device_ids.dedup();
    device_ids
}

fn discovered_cdi_gpu_device_ids() -> Vec<String> {
    let engine = ContainerEngine::from_env();
    let output = engine
        .command()
        .args(["info", "--format", "json"])
        .output()
        .unwrap_or_else(|err| panic!("failed to run {} info: {err}", engine.name()));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "{} info --format json failed with status {:?}:\n{}",
        engine.name(),
        output.status.code(),
        combined
    );

    let info: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "failed to parse {} info JSON: {err}\n{combined}",
            engine.name()
        )
    });
    let device_ids = parse_cdi_gpu_device_ids(&info);
    assert!(
        !device_ids.is_empty(),
        "{} info --format json did not report any discovered NVIDIA CDI GPU devices. \
Expected DiscoveredDevices entries with Source=cdi and ID like nvidia.com/gpu=all.",
        engine.name()
    );
    device_ids
}

fn has_cdi_gpu_device(device_id: &str) -> bool {
    discovered_cdi_gpu_device_ids()
        .iter()
        .any(|discovered| discovered == device_id)
}

fn runtime_gpu_lines(gpu_device: &str) -> Vec<String> {
    let engine = ContainerEngine::from_env();
    let image = gpu_probe_image();
    let output = engine
        .command()
        .args([
            "run",
            "--rm",
            "--device",
            gpu_device,
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
        "{} GPU probe failed for {gpu_device} with image {image} and status {:?}:\n{}",
        engine.name(),
        output.status.code(),
        combined
    );

    let lines = gpu_lines(&stdout);
    assert!(
        !lines.is_empty(),
        "{} GPU probe for {gpu_device} did not report any GPU lines with image {image}:\n{combined}",
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
    if !has_cdi_gpu_device(CDI_GPU_DEVICE_ALL) {
        eprintln!(
            "skipping default GPU request test because {CDI_GPU_DEVICE_ALL} was not discovered"
        );
        return;
    }

    let expected = runtime_gpu_lines(CDI_GPU_DEVICE_ALL);
    let actual = sandbox_gpu_lines(None).await;

    assert_eq!(
        actual, expected,
        "default GPU request should expose the same GPU lines as a plain all-GPU container"
    );
}

#[tokio::test]
async fn gpu_request_for_each_discovered_device_matches_plain_container() {
    let device_ids: Vec<_> = discovered_cdi_gpu_device_ids()
        .into_iter()
        .filter(|device_id| device_id != CDI_GPU_DEVICE_ALL)
        .collect();

    if device_ids.is_empty() {
        eprintln!(
            "skipping per-device GPU request test because no per-device NVIDIA CDI IDs were discovered"
        );
        return;
    }

    for gpu_device in device_ids {
        let expected = runtime_gpu_lines(&gpu_device);
        let actual = sandbox_gpu_lines(Some(&gpu_device)).await;
        assert_eq!(
            actual, expected,
            "GPU request for {gpu_device} should expose the same GPU lines as a plain container"
        );
    }
}

#[tokio::test]
async fn gpu_all_device_request_matches_plain_all_gpu_container() {
    if !has_cdi_gpu_device(CDI_GPU_DEVICE_ALL) {
        eprintln!(
            "skipping explicit all-GPU request test because {CDI_GPU_DEVICE_ALL} was not discovered"
        );
        return;
    }

    let expected = runtime_gpu_lines(CDI_GPU_DEVICE_ALL);
    let actual = sandbox_gpu_lines(Some(CDI_GPU_DEVICE_ALL)).await;

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

#[test]
fn parse_cdi_gpu_device_ids_reads_discovered_devices() {
    let info = serde_json::json!({
        "DiscoveredDevices": [
            {
                "Source": "cdi",
                "ID": "example.com/device=foo"
            },
            {
                "Source": "cdi",
                "ID": "nvidia.com/gpu=0"
            },
            {
                "Source": "cdi",
                "ID": "nvidia.com/gpu=all"
            }
        ]
    });

    assert_eq!(
        parse_cdi_gpu_device_ids(&info),
        vec![
            "nvidia.com/gpu=0".to_string(),
            CDI_GPU_DEVICE_ALL.to_string()
        ]
    );
}

#[test]
fn parse_cdi_gpu_device_ids_reads_lowercase_host_discovered_devices() {
    let info = serde_json::json!({
        "host": {
            "discoveredDevices": [
                {
                    "source": "cdi",
                    "id": "nvidia.com/gpu=1"
                },
                {
                    "Source": "cdi",
                    "ID": "nvidia.com/gpu=1"
                },
                {
                    "Source": "udev",
                    "ID": "nvidia.com/gpu=2"
                }
            ]
        }
    });

    assert_eq!(
        parse_cdi_gpu_device_ids(&info),
        vec!["nvidia.com/gpu=1".to_string()]
    );
}

#[test]
fn parse_cdi_gpu_device_ids_ignores_unexpected_nested_devices() {
    let info = serde_json::json!({
        "host": {
            "devices": [
                {
                    "Source": "cdi",
                    "ID": "nvidia.com/gpu=2"
                }
            ]
        }
    });

    assert!(parse_cdi_gpu_device_ids(&info).is_empty());
}
