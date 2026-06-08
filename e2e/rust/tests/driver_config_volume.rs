// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::container::{ContainerEngine, e2e_driver};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Map, Value};

const TEST_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";
const VOLUME_TARGET: &str = "/sandbox/e2e-volume";
const BIND_TARGET: &str = "/sandbox/e2e-bind";

struct VolumeGuard {
    engine: ContainerEngine,
    name: String,
}

impl VolumeGuard {
    fn create(engine: ContainerEngine, driver: &str) -> Result<Self, String> {
        let name = unique_volume_name(driver);
        run_engine(&engine, &["volume", "create", &name])?;
        Ok(Self { engine, name })
    }
}

impl Drop for VolumeGuard {
    fn drop(&mut self) {
        let _ = self
            .engine
            .command()
            .args(["volume", "rm", "-f", &self.name])
            .output();
    }
}

#[tokio::test]
async fn sandbox_mounts_existing_driver_config_volume() {
    let driver = e2e_driver().expect("OPENSHELL_E2E_DRIVER must be set by the e2e wrapper");
    assert!(
        matches!(driver.as_str(), "docker" | "podman"),
        "driver_config volume e2e requires docker or podman, got {driver}"
    );

    let engine = ContainerEngine::from_env();
    let volume = VolumeGuard::create(engine, &driver).expect("create named test volume");

    seed_volume(&volume).expect("seed named test volume");

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
    verify_volume(&volume).expect("verify sandbox wrote to named test volume");
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
    fs::write(host_dir.path().join("input.txt"), "host-bind-ok")
        .expect("seed bind mount host dir");

    let driver_config = driver_config_mount_json(
        &driver,
        serde_json::json!({
            "type": "bind",
            "source": host_dir.path(),
            "target": BIND_TARGET,
            "read_only": false
        }),
    );
    let mut sandbox = SandboxGuard::create(&[
        "--no-keep",
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

fn seed_volume(volume: &VolumeGuard) -> Result<(), String> {
    run_engine(
        &volume.engine,
        &[
            "run",
            "--rm",
            "--user",
            "0:0",
            "--volume",
            &format!("{}:/vol", volume.name),
            "--entrypoint",
            "sh",
            TEST_IMAGE,
            "-lc",
            "set -eu; chmod 0777 /vol; printf host-volume-ok > /vol/input.txt",
        ],
    )?;
    Ok(())
}

fn verify_volume(volume: &VolumeGuard) -> Result<(), String> {
    let output = run_engine(
        &volume.engine,
        &[
            "run",
            "--rm",
            "--user",
            "0:0",
            "--volume",
            &format!("{}:/vol:ro", volume.name),
            "--entrypoint",
            "sh",
            TEST_IMAGE,
            "-lc",
            "set -eu; test \"$(cat /vol/input.txt)\" = host-volume-ok; test \"$(cat /vol/output.txt)\" = sandbox-volume-ok; echo volume-ok",
        ],
    )?;
    if !output.contains("volume-ok") {
        return Err(format!(
            "volume verification did not print expected marker:\n{output}"
        ));
    }
    Ok(())
}

fn run_engine(engine: &ContainerEngine, args: &[&str]) -> Result<String, String> {
    let output = engine
        .command()
        .args(args)
        .output()
        .map_err(|err| format!("spawn {} {}: {err}", engine.name(), args.join(" ")))?;
    engine_output(engine, args, &output)
}

fn engine_output(
    engine: &ContainerEngine,
    args: &[&str],
    output: &Output,
) -> Result<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    if output.status.success() {
        return Ok(combined);
    }
    Err(format!(
        "{} {} failed (exit {:?}):\n{combined}",
        engine.name(),
        args.join(" "),
        output.status.code()
    ))
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

fn driver_config_mount_json(driver: &str, mount: Value) -> String {
    let mut root = Map::new();
    root.insert(
        driver.to_string(),
        serde_json::json!({
            "mounts": [mount]
        }),
    );
    Value::Object(root).to_string()
}
