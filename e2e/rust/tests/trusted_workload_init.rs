// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

//! Runtime-neutral trusted workload initialization contract coverage.
//!
//! The focused Docker and Podman wrappers build the same hostile image and
//! register the same immutable contract. Broad local-driver suites compile
//! this test but skip it unless that fixture registration is present.

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{ContainerEngine, e2e_driver};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::timeout;

const CONTRACT_ID: &str = "openshell.e2e.v1";
const PAYLOAD: &[u8] = b"agent-neutral-runtime-contract-v1\n";

#[tokio::test]
async fn trusted_workload_initialization_contract() {
    let Some(image) = std::env::var("OPENSHELL_E2E_TRUSTED_INIT_IMAGE").ok() else {
        eprintln!(
            "skipping trusted workload initialization: focused fixture registration is not active"
        );
        return;
    };
    assert_immutable_image_id(&image);

    let driver = e2e_driver().expect("local container driver e2e must identify its driver");
    assert!(
        matches!(driver.as_str(), "docker" | "podman"),
        "trusted init e2e requires docker or podman, got {driver}"
    );

    let mut payload = tempfile::NamedTempFile::new().expect("create trusted init payload");
    payload
        .write_all(PAYLOAD)
        .expect("write trusted init payload");
    payload.flush().expect("flush trusted init payload");
    let payload_path = payload
        .path()
        .to_str()
        .expect("trusted init payload path must be utf-8");

    let name_prefix = unique_name_prefix(&driver);
    assert_unregistered_contract_rejected(&image, payload_path, &name_prefix).await;
    assert_caller_mount_rejected(&driver, &image, payload_path, &name_prefix).await;
    assert_registered_initializer_runs(&driver, &image, payload_path, &name_prefix).await;
    assert_ordinary_create_unchanged(&image, &name_prefix).await;
}

async fn assert_unregistered_contract_rejected(image: &str, payload_path: &str, name_prefix: &str) {
    let unregistered_name = format!("{name_prefix}-u");
    let unregistered = create_expect_failure(
        &unregistered_name,
        &[
            "--name",
            &unregistered_name,
            "--from",
            image,
            "--trusted-init-contract",
            "openshell.e2e.unregistered.v1",
            "--trusted-init-payload-file",
            payload_path,
            "--no-tty",
            "--",
            "/usr/local/bin/openshell-e2e-workload-check",
        ],
    )
    .await;
    assert!(
        unregistered.contains("is not registered"),
        "unregistered contract should be rejected by the gateway:\n{unregistered}"
    );
}

async fn assert_caller_mount_rejected(
    driver: &str,
    image: &str,
    payload_path: &str,
    name_prefix: &str,
) {
    let mount_name = format!("{name_prefix}-m");
    let driver_config = format!(
        r#"{{"{driver}":{{"mounts":[{{"type":"tmpfs","target":"/sandbox/e2e-caller-mount"}}]}}}}"#
    );
    let mount_rejection = create_expect_failure(
        &mount_name,
        &[
            "--name",
            &mount_name,
            "--from",
            image,
            "--driver-config-json",
            &driver_config,
            "--trusted-init-contract",
            CONTRACT_ID,
            "--trusted-init-payload-file",
            payload_path,
            "--no-tty",
            "--",
            "/usr/local/bin/openshell-e2e-workload-check",
        ],
    )
    .await;
    assert!(
        mount_rejection.contains("driver_config mounts are not allowed")
            && mount_rejection.contains("trusted workload initialization"),
        "caller mounts should be rejected when trusted init is active:\n{mount_rejection}"
    );
}

async fn assert_registered_initializer_runs(
    driver: &str,
    image: &str,
    payload_path: &str,
    name_prefix: &str,
) {
    let positive_name = format!("{name_prefix}-p");
    let mut command = openshell_cmd();
    command
        .args([
            "sandbox",
            "create",
            "--name",
            &positive_name,
            "--from",
            image,
            "--trusted-init-contract",
            CONTRACT_ID,
            "--trusted-init-payload-file",
            payload_path,
            "--no-tty",
            "--",
            "/usr/local/bin/openshell-e2e-workload-check",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .expect("start registered trusted initializer create");

    wait_for_running_receipt(driver, &positive_name)
        .await
        .expect("observe running trusted initializer receipt");
    assert_sandbox_not_ready(&positive_name).await;

    let output = timeout(Duration::from_secs(600), child.wait_with_output())
        .await
        .expect("registered trusted initializer create timed out")
        .expect("wait for registered trusted initializer create");
    let initialized_output = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    let receipt_result = if output.status.success() {
        inspect_success_receipt(driver, &positive_name).await
    } else {
        Err("sandbox create failed before receipt inspection".to_string())
    };
    cleanup_named_sandbox(&positive_name).await;
    assert!(
        output.status.success(),
        "registered trusted initializer should complete before workload readiness:\n{initialized_output}"
    );
    assert!(
        initialized_output.contains("trusted-workload-init-e2e-ok"),
        "trusted initializer should deliver its payload and receipt without running image-owned probes:\n{initialized_output}"
    );
    assert!(
        receipt_result.is_ok(),
        "trusted initializer should leave a root-owned immutable success receipt: {}",
        receipt_result.unwrap_err()
    );
}

async fn assert_ordinary_create_unchanged(image: &str, name_prefix: &str) {
    let ordinary_name = format!("{name_prefix}-o");
    let mut ordinary = SandboxGuard::create(&[
        "--name",
        &ordinary_name,
        "--from",
        image,
        "--no-tty",
        "--",
        "/usr/local/bin/openshell-e2e-ordinary-check",
    ])
    .await
    .expect("ordinary create without trusted init should remain supported");
    let ordinary_output = strip_ansi(&ordinary.create_output);
    assert!(
        ordinary_output.contains("ordinary-create-e2e-ok"),
        "ordinary create should not receive trusted init state:\n{ordinary_output}"
    );
    ordinary.cleanup().await;
}

async fn create_expect_failure(name: &str, args: &[&str]) -> String {
    let mut command = openshell_cmd();
    command
        .arg("sandbox")
        .arg("create")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = command.output().await.expect("run failing sandbox create");
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));

    cleanup_named_sandbox(name).await;
    assert!(
        !output.status.success(),
        "sandbox create unexpectedly succeeded:\n{combined}"
    );
    combined
}

async fn cleanup_named_sandbox(name: &str) {
    let mut command = openshell_cmd();
    command
        .args(["sandbox", "delete", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = command.status().await;
}

async fn wait_for_running_receipt(driver: &str, sandbox_name: &str) -> Result<(), String> {
    let engine = ContainerEngine::from_env()?;
    assert_eq!(
        engine.name(),
        driver,
        "container engine must match the active local driver"
    );
    let label = format!("label=openshell.ai/sandbox-name={sandbox_name}");

    timeout(Duration::from_secs(90), async {
        loop {
            let list = engine
                .command()
                .args(["ps", "--quiet", "--filter", &label])
                .output()
                .map_err(|error| format!("list {driver} sandbox containers: {error}"))?;
            if !list.status.success() {
                return Err(format!(
                    "{driver} ps failed:\n{}",
                    String::from_utf8_lossy(&list.stderr)
                ));
            }

            for container_id in String::from_utf8_lossy(&list.stdout).split_whitespace() {
                let receipt = engine
                    .command()
                    .args([
                        "exec",
                        container_id,
                        "/usr/bin/grep",
                        "-Fq",
                        r#""status":"running""#,
                        "/var/lib/openshell/trusted-init/receipt.json",
                    ])
                    .output()
                    .map_err(|error| {
                        format!("inspect {driver} trusted initializer receipt: {error}")
                    })?;
                if receipt.status.success() {
                    return Ok(());
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "trusted initializer never exposed its running receipt".to_string())?
}

async fn inspect_success_receipt(driver: &str, sandbox_name: &str) -> Result<(), String> {
    let engine = ContainerEngine::from_env()?;
    assert_eq!(
        engine.name(),
        driver,
        "container engine must match the active local driver"
    );
    let label = format!("label=openshell.ai/sandbox-name={sandbox_name}");
    let list = engine
        .command()
        .args(["ps", "--quiet", "--filter", &label])
        .output()
        .map_err(|error| format!("list {driver} sandbox containers: {error}"))?;
    if !list.status.success() {
        return Err(format!(
            "{driver} ps failed:\n{}",
            String::from_utf8_lossy(&list.stderr)
        ));
    }
    let container_id = String::from_utf8_lossy(&list.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| "trusted initializer container is not running".to_string())?;
    let receipt_path = "/var/lib/openshell/trusted-init/receipt.json";
    let receipt = engine
        .command()
        .args([
            "exec",
            &container_id,
            "/usr/bin/grep",
            "-Fq",
            r#""status":"success""#,
            receipt_path,
        ])
        .output()
        .map_err(|error| format!("inspect {driver} trusted initializer receipt: {error}"))?;
    if !receipt.status.success() {
        return Err(format!(
            "trusted initializer success receipt missing:\n{}",
            String::from_utf8_lossy(&receipt.stderr)
        ));
    }
    let ownership = engine
        .command()
        .args([
            "exec",
            &container_id,
            "/usr/bin/stat",
            "-c",
            "%u:%g:%a",
            receipt_path,
        ])
        .output()
        .map_err(|error| format!("stat {driver} trusted initializer receipt: {error}"))?;
    if !ownership.status.success() {
        return Err(format!(
            "trusted initializer receipt stat failed:\n{}",
            String::from_utf8_lossy(&ownership.stderr)
        ));
    }
    let ownership = String::from_utf8_lossy(&ownership.stdout);
    if ownership.trim() != "0:0:444" {
        return Err(format!(
            "trusted initializer receipt ownership/mode was {}, expected 0:0:444",
            ownership.trim()
        ));
    }
    Ok(())
}

async fn assert_sandbox_not_ready(name: &str) {
    let mut command = openshell_cmd();
    command
        .args(["sandbox", "get", name, "--output", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .expect("read sandbox phase during trusted initialization");
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        output.status.success(),
        "sandbox get should succeed while trusted initializer is running:\n{combined}"
    );
    let sandbox: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("sandbox get should return JSON");
    assert_ne!(
        sandbox["phase"].as_str(),
        Some("Ready"),
        "sandbox must remain non-Ready while the trusted initializer receipt is running:\n{combined}"
    );
}

fn assert_immutable_image_id(image: &str) {
    let digest = image
        .strip_prefix("sha256:")
        .expect("fixture image must be a bare sha256 image ID");
    assert_eq!(
        digest.len(),
        64,
        "fixture image digest must be 64 hex bytes"
    );
    assert!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "fixture image digest must be hexadecimal"
    );
}

fn unique_name_prefix(driver: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let driver_initial = driver
        .chars()
        .next()
        .expect("validated driver name is non-empty");
    let discriminator = timestamp & u128::from(u32::MAX);
    format!("ti{driver_initial}{discriminator:08x}")
}
