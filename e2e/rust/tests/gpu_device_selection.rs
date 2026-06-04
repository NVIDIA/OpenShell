// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-gpu")]

//! GPU device selection e2e tests.
//!
//! Requires a GPU-backed gateway and a sandbox image containing `nvidia-smi`.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{ContainerEngine, e2e_driver};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Map, Value};
use tokio::time::timeout;

const SANDBOX_CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const CDI_GPU_DEVICE_ALL: &str = "nvidia.com/gpu=all";
const CDI_GPU_DEVICE_PREFIX: &str = "nvidia.com/gpu=";
const GPU_PROBE_IMAGE_ENV: &str = "OPENSHELL_E2E_GPU_PROBE_IMAGE";
const DEFAULT_GPU_PROBE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:noble-20251013";

fn gpu_lines(output: &str) -> Vec<String> {
    strip_ansi(output)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("GPU "))
        .map(ToOwned::to_owned)
        .collect()
}

fn gpu_probe_image() -> String {
    std::env::var(GPU_PROBE_IMAGE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_GPU_PROBE_IMAGE.to_string())
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

fn local_podman_cdi_gpu_device_ids() -> Vec<String> {
    let mut device_ids = std::fs::read_dir("/dev")
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let index = name.strip_prefix("nvidia")?;
            (!index.is_empty() && index.chars().all(|ch| ch.is_ascii_digit()))
                .then(|| format!("{CDI_GPU_DEVICE_PREFIX}{index}"))
        })
        .collect::<Vec<_>>();
    if local_podman_all_gpu_default_supported() {
        device_ids.push(CDI_GPU_DEVICE_ALL.to_string());
    }
    device_ids.sort();
    device_ids.dedup();
    device_ids
}

fn local_podman_all_gpu_default_supported() -> bool {
    std::path::Path::new("/dev/dxg").exists()
}

fn uses_local_podman_inventory(engine: &ContainerEngine) -> bool {
    engine.name().rsplit('/').next() == Some("podman")
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

fn container_engine_info(engine: &ContainerEngine) -> Value {
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

    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "failed to parse {} info JSON: {err}\n{combined}",
            engine.name()
        )
    })
}

fn info_string<'a>(info: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| info.get(*key).and_then(Value::as_str))
}

fn text_reports_wsl2(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("wsl2") || value.contains("microsoft-standard")
}

fn docker_info_reports_wsl2(info: &Value) -> bool {
    [
        info_string(info, &["KernelVersion", "kernelVersion", "kernel_version"]),
        info_string(
            info,
            &["OperatingSystem", "operatingSystem", "operating_system"],
        ),
    ]
    .into_iter()
    .flatten()
    .any(text_reports_wsl2)
}

fn all_gpu_default_allowed() -> bool {
    let engine = ContainerEngine::from_env();
    if uses_local_podman_inventory(&engine) {
        return local_podman_all_gpu_default_supported();
    }

    docker_info_reports_wsl2(&container_engine_info(&engine))
}

fn discovered_cdi_gpu_device_ids() -> Vec<String> {
    let engine = ContainerEngine::from_env();
    if uses_local_podman_inventory(&engine) {
        let device_ids = local_podman_cdi_gpu_device_ids();
        assert!(
            !device_ids.is_empty(),
            "local Podman GPU e2e tests require /dev/nvidiaN device nodes or \
/dev/dxg so bare --gpu can be mapped to a supported NVIDIA CDI device"
        );
        return device_ids;
    }

    let info = container_engine_info(&engine);
    let device_ids = parse_cdi_gpu_device_ids(&info);
    assert!(
        !device_ids.is_empty(),
        "{} info --format json did not report any discovered NVIDIA CDI GPU devices. \
Expected DiscoveredDevices entries with Source=cdi and ID like nvidia.com/gpu=0.",
        engine.name()
    );
    device_ids
}

fn default_cdi_gpu_device_id(device_ids: &[String], allow_all_devices: bool) -> Option<String> {
    let mut indexed = device_ids
        .iter()
        .filter_map(|device_id| {
            let suffix = device_id.strip_prefix(CDI_GPU_DEVICE_PREFIX)?;
            let index = suffix.parse::<u64>().ok()?;
            Some((index, device_id.clone()))
        })
        .collect::<Vec<_>>();
    if !indexed.is_empty() {
        indexed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        return indexed.into_iter().map(|(_, device_id)| device_id).next();
    }

    let mut named = device_ids
        .iter()
        .filter(|device_id| {
            device_id.starts_with(CDI_GPU_DEVICE_PREFIX)
                && device_id.as_str() != CDI_GPU_DEVICE_ALL
        })
        .cloned()
        .collect::<Vec<_>>();
    if !named.is_empty() {
        named.sort();
        return named.into_iter().next();
    }

    (allow_all_devices
        && device_ids
            .iter()
            .any(|device_id| device_id == CDI_GPU_DEVICE_ALL))
    .then(|| CDI_GPU_DEVICE_ALL.to_string())
}

fn has_cdi_gpu_device(device_id: &str) -> bool {
    discovered_cdi_gpu_device_ids()
        .iter()
        .any(|discovered| discovered == device_id)
}

fn e2e_driver_config_key() -> &'static str {
    match e2e_driver().as_deref() {
        Some("podman") => "podman",
        _ => "docker",
    }
}

fn cdi_devices_driver_config_json(device_ids: &[&str]) -> String {
    serde_json::json!({
        e2e_driver_config_key(): {
            "cdi_devices": device_ids
        }
    })
    .to_string()
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
    let driver_config_json;
    if let Some(gpu_device) = gpu_device {
        driver_config_json = cdi_devices_driver_config_json(&[gpu_device]);
        args.push("--driver-config-json");
        args.push(driver_config_json.as_str());
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
async fn gpu_request_without_device_matches_plain_default_gpu_container() {
    let device_ids = discovered_cdi_gpu_device_ids();
    let Some(default_gpu_device) = default_cdi_gpu_device_id(&device_ids, all_gpu_default_allowed())
    else {
        eprintln!("skipping default GPU request test because no selectable GPU ID was discovered");
        return;
    };

    let expected = runtime_gpu_lines(&default_gpu_device);
    let actual = sandbox_gpu_lines(None).await;

    assert_eq!(
        actual, expected,
        "default GPU request should expose the same GPU lines as a plain container using {default_gpu_device}"
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
    let driver_config_json = cdi_devices_driver_config_json(&["nvidia.com/gpu=invalid"]);
    let args = vec![
        "--gpu",
        "--driver-config-json",
        driver_config_json.as_str(),
        "--",
        "sh",
        "-lc",
        "nvidia-smi -L",
    ];
    let output = sandbox_create_output(&args).await;
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

#[test]
fn docker_info_reports_wsl2_uses_kernel_and_operating_system_only() {
    let info = serde_json::json!({
        "KernelVersion": "5.15.153.1-microsoft-standard-WSL2",
        "OperatingSystem": "Docker Desktop",
        "OSType": "linux",
        "Name": "docker-daemon",
        "Labels": ["com.example.platform=linux"]
    });

    assert!(docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_ignores_daemon_name_and_labels() {
    let info = serde_json::json!({
        "KernelVersion": "6.8.0-60-generic",
        "OperatingSystem": "Ubuntu 24.04.4 LTS",
        "OSType": "wsl",
        "Name": "wsl-docker-daemon",
        "Labels": ["com.example.platform=wsl2"]
    });

    assert!(!docker_info_reports_wsl2(&info));
}
