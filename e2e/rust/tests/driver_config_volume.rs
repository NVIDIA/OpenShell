// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, Mount, MountTypeEnum, VolumeCreateRequest};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptionsBuilder, LogsOptions, RemoveContainerOptions,
    RemoveVolumeOptionsBuilder, StartContainerOptions, WaitContainerOptions,
};
use futures_util::TryStreamExt;
use openshell_e2e::harness::container::e2e_driver;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Map, Value};

const TEST_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";
const VOLUME_TARGET: &str = "/sandbox/e2e-volume";
const BIND_TARGET: &str = "/sandbox/e2e-bind";

struct VolumeGuard {
    docker: Docker,
    name: String,
}

impl VolumeGuard {
    async fn create(driver: &str) -> Result<Self, String> {
        let name = unique_volume_name(driver);
        let docker = connect_container_api(driver).await?;
        docker
            .create_volume(VolumeCreateRequest {
                name: Some(name.clone()),
                ..Default::default()
            })
            .await
            .map_err(|err| format!("create {driver} volume {name}: {err}"))?;
        Ok(Self { docker, name })
    }
}

impl Drop for VolumeGuard {
    fn drop(&mut self) {
        let docker = self.docker.clone();
        let name = self.name.clone();
        tokio::spawn(async move {
            let _ = docker
                .remove_volume(
                    &name,
                    Some(RemoveVolumeOptionsBuilder::new().force(true).build()),
                )
                .await;
        });
    }
}

#[tokio::test]
async fn sandbox_mounts_existing_driver_config_volume() {
    let driver = e2e_driver().expect("OPENSHELL_E2E_DRIVER must be set by the e2e wrapper");
    assert!(
        matches!(driver.as_str(), "docker" | "podman"),
        "driver_config volume e2e requires docker or podman, got {driver}"
    );

    let volume = VolumeGuard::create(&driver)
        .await
        .expect("create named test volume");

    seed_volume(&volume).await.expect("seed named test volume");

    let driver_config = format!(
        r#"{{"{driver}":{{"mounts":[{{"type":"volume","source":"{}","target":"{VOLUME_TARGET}","read_only":false}}]}}}}"#,
        volume.name
    );
    let mut sandbox = SandboxGuard::create(&[
        "--no-keep",
        "--driver-config-json",
        &driver_config,
        "--",
        "sh",
        "-lc",
        "set -eu; test \"$(cat /sandbox/e2e-volume/input.txt)\" = host-volume-ok; printf sandbox-volume-ok > /sandbox/e2e-volume/output.txt; cat /sandbox/e2e-volume/output.txt",
    ])
    .await
    .expect("sandbox create with driver-config volume");

    assert!(
        sandbox.create_output.contains("sandbox-volume-ok"),
        "sandbox should read and write the mounted volume:\n{}",
        sandbox.create_output
    );

    sandbox.cleanup().await;
    verify_volume(&volume)
        .await
        .expect("verify sandbox wrote to named test volume");
}

#[tokio::test]
async fn sandbox_mounts_enabled_driver_config_bind() {
    let driver = e2e_driver().expect("OPENSHELL_E2E_DRIVER must be set by the e2e wrapper");
    assert!(
        matches!(driver.as_str(), "docker" | "podman"),
        "driver_config bind e2e requires docker or podman, got {driver}"
    );

    let cwd = std::env::current_dir().expect("resolve current dir");
    let host_dir = tempfile::Builder::new()
        .prefix("openshell-e2e-driver-config-bind-")
        .tempdir_in(cwd)
        .expect("create bind mount host dir");
    fs::set_permissions(host_dir.path(), fs::Permissions::from_mode(0o777))
        .expect("make bind mount host dir writable by sandbox user");
    let input_path = host_dir.path().join("input.txt");
    fs::write(&input_path, "host-bind-ok").expect("seed bind mount host dir");
    fs::set_permissions(&input_path, fs::Permissions::from_mode(0o666))
        .expect("make bind mount input readable by sandbox user");

    let bind_source = bind_mount_source_path(&driver, host_dir.path());
    let bind_mount = serde_json::json!({
        "type": "bind",
        "source": bind_source,
        "target": BIND_TARGET,
        "read_only": false
    });
    let driver_config = driver_config_mount_json(&driver, &bind_mount);
    // Host bind mounts are explicitly unsafe: this test validates driver mount
    // wiring, not Landlock enforcement over Docker Desktop's fakeowner mounts.
    let policy = write_bind_mount_policy().expect("write bind mount policy");
    let policy_path = policy.path().to_str().expect("policy path must be utf-8");
    let mut sandbox = SandboxGuard::create(&[
        "--no-keep",
        "--policy",
        policy_path,
        "--driver-config-json",
        &driver_config,
        "--",
        "sh",
        "-lc",
        "set -eu; test \"$(cat /sandbox/e2e-bind/input.txt)\" = host-bind-ok; printf sandbox-bind-ok > /sandbox/e2e-bind/output.txt; cat /sandbox/e2e-bind/output.txt",
    ])
    .await
    .expect("sandbox create with driver-config bind mount");

    assert!(
        sandbox.create_output.contains("sandbox-bind-ok"),
        "sandbox should read and write the bind mount:\n{}",
        sandbox.create_output
    );

    sandbox.cleanup().await;
    let output = fs::read_to_string(host_dir.path().join("output.txt"))
        .expect("read sandbox output from bind mount host dir");
    assert_eq!(output, "sandbox-bind-ok");
}

fn write_bind_mount_policy() -> Result<tempfile::NamedTempFile, String> {
    let mut file =
        tempfile::NamedTempFile::new().map_err(|err| format!("create bind policy: {err}"))?;
    file.write_all(
        br"version: 1

filesystem_policy:
  include_workdir: false

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox
",
    )
    .map_err(|err| format!("write bind policy: {err}"))?;
    Ok(file)
}

async fn seed_volume(volume: &VolumeGuard) -> Result<(), String> {
    run_volume_container(
        volume,
        "seed",
        false,
        "set -eu; chmod 0777 /vol; printf host-volume-ok > /vol/input.txt",
    )
    .await?;
    Ok(())
}

async fn verify_volume(volume: &VolumeGuard) -> Result<(), String> {
    let output = run_volume_container(
        volume,
        "verify",
        true,
        "set -eu; test \"$(cat /vol/input.txt)\" = host-volume-ok; test \"$(cat /vol/output.txt)\" = sandbox-volume-ok; echo volume-ok",
    )
    .await?;
    if !output.contains("volume-ok") {
        return Err(format!(
            "volume verification did not print expected marker:\n{output}"
        ));
    }
    Ok(())
}

async fn run_volume_container(
    volume: &VolumeGuard,
    purpose: &str,
    read_only: bool,
    script: &str,
) -> Result<String, String> {
    ensure_test_image(&volume.docker).await?;

    let container_name = format!("{}-{purpose}", volume.name);
    let create_options = CreateContainerOptionsBuilder::new()
        .name(&container_name)
        .build();
    let host_config = HostConfig {
        mounts: Some(vec![Mount {
            target: Some("/vol".to_string()),
            source: Some(volume.name.clone()),
            typ: Some(MountTypeEnum::VOLUME),
            read_only: Some(read_only),
            ..Default::default()
        }]),
        ..Default::default()
    };
    volume
        .docker
        .create_container(
            Some(create_options),
            ContainerCreateBody {
                image: Some(TEST_IMAGE.to_string()),
                user: Some("0:0".to_string()),
                entrypoint: Some(vec!["sh".to_string()]),
                cmd: Some(vec!["-lc".to_string(), script.to_string()]),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                host_config: Some(host_config),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| format!("create helper container {container_name}: {err}"))?;

    let result = run_created_container(volume, &container_name).await;
    let remove_result = volume
        .docker
        .remove_container(&container_name, None::<RemoveContainerOptions>)
        .await;

    match (result, remove_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Ok(_), Err(err)) => Err(format!("remove helper container {container_name}: {err}")),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(remove_err)) => Err(format!(
            "{err}\nremove helper container {container_name}: {remove_err}"
        )),
    }
}

async fn ensure_test_image(docker: &Docker) -> Result<(), String> {
    if docker.inspect_image(TEST_IMAGE).await.is_ok() {
        return Ok(());
    }

    let pull_events = docker
        .create_image(
            Some(
                CreateImageOptionsBuilder::new()
                    .from_image(TEST_IMAGE)
                    .build(),
            ),
            None,
            None,
        )
        .try_collect::<Vec<_>>()
        .await
        .map_err(|err| format!("pull helper image {TEST_IMAGE}: {err}"))?;

    let pull_errors = pull_events
        .iter()
        .filter_map(|event| {
            event
                .error_detail
                .as_ref()
                .and_then(|detail| detail.message.as_deref())
        })
        .collect::<Vec<_>>();
    if pull_errors.is_empty() {
        return Ok(());
    }

    Err(format!(
        "pull helper image {TEST_IMAGE} failed:\n{}",
        pull_errors.join("\n")
    ))
}

async fn run_created_container(
    volume: &VolumeGuard,
    container_name: &str,
) -> Result<String, String> {
    volume
        .docker
        .start_container(container_name, None::<StartContainerOptions>)
        .await
        .map_err(|err| format!("start helper container {container_name}: {err}"))?;

    let wait_result = volume
        .docker
        .wait_container(container_name, None::<WaitContainerOptions>)
        .try_collect::<Vec<_>>()
        .await;
    let logs = volume
        .docker
        .logs(
            container_name,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                tail: "all".to_string(),
                ..Default::default()
            }),
        )
        .try_collect::<Vec<_>>()
        .await
        .map(|chunks| {
            chunks
                .into_iter()
                .map(|chunk| chunk.to_string())
                .collect::<String>()
        });

    match (wait_result, logs) {
        (Ok(_), Ok(output)) => Ok(output),
        (Ok(_), Err(err)) => Err(format!(
            "read helper container {container_name} logs: {err}"
        )),
        (Err(err), Ok(output)) => Err(format!(
            "helper container {container_name} failed: {err}\n{output}"
        )),
        (Err(err), Err(log_err)) => Err(format!(
            "helper container {container_name} failed: {err}\nread logs failed: {log_err}"
        )),
    }
}

async fn connect_container_api(driver: &str) -> Result<Docker, String> {
    let docker = match driver {
        "docker" => Docker::connect_with_local_defaults()
            .map_err(|err| format!("connect to Docker API: {err}"))?,
        "podman" => {
            let socket = podman_socket_path();
            let socket_display = socket.display().to_string();
            Docker::connect_with_unix(
                socket
                    .to_str()
                    .ok_or_else(|| format!("podman socket path is not UTF-8: {socket_display}"))?,
                120,
                bollard::API_DEFAULT_VERSION,
            )
            .map_err(|err| format!("connect to Podman Docker-compatible API: {err}"))?
        }
        other => return Err(format!("unsupported e2e driver for volume API: {other}")),
    };
    docker
        .ping()
        .await
        .map_err(|err| format!("ping {driver} Docker-compatible API: {err}"))?;
    Ok(docker)
}

fn podman_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("OPENSHELL_PODMAN_SOCKET") {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").unwrap_or_default();
        PathBuf::from(home).join(".local/share/containers/podman/machine/podman.sock")
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
            || {
                let uid = std::process::Command::new("id")
                    .arg("-u")
                    .output()
                    .ok()
                    .and_then(|output| {
                        String::from_utf8(output.stdout)
                            .ok()
                            .map(|value| value.trim().to_string())
                    })
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "1000".to_string());
                PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"))
            },
            |xdg| PathBuf::from(xdg).join("podman/podman.sock"),
        )
    }
}

fn unique_volume_name(driver: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    format!(
        "openshell-e2e-driver-config-volume-{driver}-{}-{nanos}",
        std::process::id()
    )
}

fn driver_config_mount_json(driver: &str, mount: &Value) -> String {
    let mut root = Map::new();
    root.insert(
        driver.to_string(),
        serde_json::json!({
            "mounts": [mount]
        }),
    );
    Value::Object(root).to_string()
}

fn bind_mount_source_path(driver: &str, path: &Path) -> PathBuf {
    if driver == "docker" {
        github_actions_host_work_path(path).unwrap_or_else(|| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

fn github_actions_host_work_path(path: &Path) -> Option<PathBuf> {
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() != Some("true") {
        return None;
    }

    let relative = path.strip_prefix("/__w").ok()?;
    let mapped = Path::new("/home/runner/_work").join(relative);
    mapped.exists().then_some(mapped)
}
