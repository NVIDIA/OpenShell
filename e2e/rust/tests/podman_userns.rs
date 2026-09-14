// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

use std::path::PathBuf;
use std::time::Duration;

use openshell_e2e::harness::cli::wait_for_healthy;
use openshell_e2e::harness::container::is_e2e_driver;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serial_test::serial;

const READY_MARKER: &str = "podman-userns-ready";

struct GatewayUsernsConfig {
    config_path: PathBuf,
    original: Vec<u8>,
    restored: bool,
}

impl GatewayUsernsConfig {
    fn config_path_from_args() -> Result<PathBuf, String> {
        let args_file = std::env::var("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .map_err(|_| "OPENSHELL_E2E_GATEWAY_ARGS_FILE must be set".to_string())?;
        let raw = std::fs::read(&args_file)
            .map_err(|err| format!("read gateway args file '{args_file}': {err}"))?;
        let args: Vec<String> = raw
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect();
        args.iter()
            .position(|arg| arg == "--config")
            .and_then(|index| args.get(index + 1))
            .map(PathBuf::from)
            .ok_or_else(|| format!("no --config argument in gateway args file '{args_file}'"))
    }

    async fn apply(extra_toml: &str) -> Result<Self, String> {
        let config_path = Self::config_path_from_args()?;
        let original = std::fs::read(&config_path)
            .map_err(|err| format!("read gateway config '{}': {err}", config_path.display()))?;

        let config_str = String::from_utf8_lossy(&original);
        let lines: Vec<&str> = config_str.lines().collect();

        let section_idx = lines
            .iter()
            .position(|l| {
                let t = l.trim();
                t.starts_with('[') && t.contains("openshell.drivers.podman")
            })
            .ok_or_else(|| {
                format!(
                    "gateway config '{}' has no [openshell.drivers.podman] section",
                    config_path.display(),
                )
            })?;

        let insert_at = lines[section_idx + 1..]
            .iter()
            .position(|l| l.trim_start().starts_with('['))
            .map_or(lines.len(), |rel| section_idx + 1 + rel);

        let mut updated = String::new();
        for line in &lines[..insert_at] {
            updated.push_str(line);
            updated.push('\n');
        }
        updated.push_str(extra_toml);
        if !extra_toml.ends_with('\n') {
            updated.push('\n');
        }
        for line in &lines[insert_at..] {
            updated.push_str(line);
            updated.push('\n');
        }
        let updated = updated.into_bytes();
        std::fs::write(&config_path, &updated)
            .map_err(|err| format!("write gateway config '{}': {err}", config_path.display()))?;

        let guard = Self {
            config_path,
            original,
            restored: false,
        };
        restart_gateway().await?;
        Ok(guard)
    }

    async fn restore(&mut self) -> Result<(), String> {
        if self.restored {
            return Ok(());
        }
        std::fs::write(&self.config_path, &self.original).map_err(|err| {
            format!(
                "restore gateway config '{}': {err}",
                self.config_path.display()
            )
        })?;
        restart_gateway().await?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for GatewayUsernsConfig {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        let _ = std::fs::write(&self.config_path, &self.original);
        if let Ok(Some(gateway)) = ManagedGateway::from_env() {
            let _ = gateway.stop();
            let _ = gateway.start();
        }
    }
}

fn has_subordinate_ids() -> bool {
    if nix::unistd::getuid().is_root() {
        return true;
    }
    let username = std::env::var("USER").unwrap_or_default();
    let uid = nix::unistd::getuid().to_string();
    let Ok(subuid) = std::fs::read_to_string("/etc/subuid") else {
        return false;
    };
    subuid
        .lines()
        .any(|l| l.starts_with(&format!("{username}:")) || l.starts_with(&format!("{uid}:")))
}

async fn restart_gateway() -> Result<(), String> {
    let gateway = ManagedGateway::from_env()?
        .ok_or_else(|| "managed gateway metadata disappeared".to_string())?;
    gateway.stop()?;
    gateway.start()?;
    wait_for_healthy(Duration::from_secs(120)).await
}

#[tokio::test]
#[serial]
async fn podman_userns_keep_id() {
    if !is_e2e_driver("podman") {
        eprintln!("Skipping Podman userns test: e2e driver is not podman");
        return;
    }
    if !has_subordinate_ids() {
        eprintln!("Skipping: no subordinate UID/GID ranges available");
        return;
    }

    let mut userns_config = GatewayUsernsConfig::apply("userns = \"keep-id\"")
        .await
        .expect("apply userns gateway config");

    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--no-tty"],
        &["sh", "-c", &format!("echo {READY_MARKER}; sleep infinity")],
        READY_MARKER,
    )
    .await
    .expect("create sandbox with userns=keep-id");

    let id_output = sandbox
        .exec(&["id", "-u"])
        .await
        .expect("exec id -u in sandbox");
    let sandbox_uid = strip_ansi(&id_output).trim().to_string();
    assert!(
        sandbox_uid.parse::<u32>().is_ok(),
        "sandbox should report a numeric UID, got '{sandbox_uid}'"
    );

    let cat_output = sandbox
        .exec(&["cat", "/proc/self/uid_map"])
        .await
        .expect("exec cat /proc/self/uid_map in sandbox");
    let uid_map = strip_ansi(&cat_output).trim().to_string();
    let mapping_count = uid_map.lines().count();
    assert!(
        mapping_count >= 1,
        "userns=keep-id should produce UID mappings, got {mapping_count}: {uid_map}"
    );

    sandbox.cleanup().await;
    userns_config
        .restore()
        .await
        .expect("restore gateway config");
}

#[tokio::test]
#[serial]
async fn podman_userns_auto() {
    if !is_e2e_driver("podman") {
        eprintln!("Skipping Podman userns test: e2e driver is not podman");
        return;
    }
    if !has_subordinate_ids() {
        eprintln!("Skipping: no subordinate UID/GID ranges available");
        return;
    }

    let mut userns_config = GatewayUsernsConfig::apply("userns = \"auto\"")
        .await
        .expect("apply userns gateway config");

    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--no-tty"],
        &["sh", "-c", &format!("echo {READY_MARKER}; sleep infinity")],
        READY_MARKER,
    )
    .await
    .expect("create sandbox with userns=auto");

    let cat_output = sandbox
        .exec(&["cat", "/proc/self/uid_map"])
        .await
        .expect("exec cat /proc/self/uid_map in sandbox");
    let uid_map = strip_ansi(&cat_output).trim().to_string();
    let mapping_count = uid_map.lines().count();
    assert!(
        mapping_count >= 1,
        "userns=auto should produce UID mappings, got {mapping_count}: {uid_map}"
    );

    let id_output = sandbox
        .exec(&["id", "-u"])
        .await
        .expect("exec id -u in sandbox");
    let sandbox_uid = strip_ansi(&id_output).trim().to_string();
    assert!(
        sandbox_uid.parse::<u32>().is_ok(),
        "sandbox should report a numeric UID, got '{sandbox_uid}'"
    );

    sandbox.cleanup().await;
    userns_config
        .restore()
        .await
        .expect("restore gateway config");
}

#[tokio::test]
#[serial]
async fn podman_userns_private() {
    if !is_e2e_driver("podman") {
        eprintln!("Skipping Podman userns test: e2e driver is not podman");
        return;
    }
    if !has_subordinate_ids() {
        eprintln!("Skipping: no subordinate UID/GID ranges available");
        return;
    }

    let extra_config = "userns = \"private\"\n\
         uidmap = [\"0:0:1\", \"1:1:65535\"]\n\
         gidmap = [\"0:0:1\", \"1:1:65535\"]";
    let mut userns_config = GatewayUsernsConfig::apply(&extra_config)
        .await
        .expect("apply userns gateway config");

    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--no-tty"],
        &["sh", "-c", &format!("echo {READY_MARKER}; sleep infinity")],
        READY_MARKER,
    )
    .await
    .expect("create sandbox with userns=private");

    let id_output = sandbox
        .exec(&["id", "-u"])
        .await
        .expect("exec id -u in sandbox");
    let sandbox_uid = strip_ansi(&id_output).trim().to_string();
    assert!(
        sandbox_uid.parse::<u32>().is_ok(),
        "sandbox should report a numeric UID, got '{sandbox_uid}'"
    );

    let cat_output = sandbox
        .exec(&["cat", "/proc/self/uid_map"])
        .await
        .expect("exec cat /proc/self/uid_map in sandbox");
    let uid_map = strip_ansi(&cat_output).trim().to_string();
    let mapping_count = uid_map.lines().count();
    assert!(
        mapping_count >= 2,
        "userns=private should produce at least 2 UID mappings, got {mapping_count}: {uid_map}"
    );

    sandbox.cleanup().await;
    userns_config
        .restore()
        .await
        .expect("restore gateway config");
}
