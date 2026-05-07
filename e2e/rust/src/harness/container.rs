// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Container-engine helpers for Rust e2e tests.
//!
//! Most e2e tests should exercise the `OpenShell` gateway contract rather than a
//! specific local container runtime. This module keeps small support containers
//! and container-engine selection aligned between Docker- and Podman-backed
//! gateway runs.

use std::process::Command;
use std::time::Duration;

use tokio::time::{interval, timeout};

use super::port::find_free_port;

const DEFAULT_TEST_SERVER_IMAGE: &str =
    "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";

#[must_use]
pub fn e2e_driver() -> Option<String> {
    std::env::var("OPENSHELL_E2E_DRIVER")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

#[must_use]
pub fn is_e2e_driver(driver: &str) -> bool {
    e2e_driver().as_deref() == Some(driver)
}

#[derive(Clone, Debug)]
pub struct ContainerEngine {
    binary: String,
}

impl ContainerEngine {
    #[must_use]
    pub fn from_env() -> Self {
        let binary = std::env::var("OPENSHELL_E2E_CONTAINER_ENGINE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| match e2e_driver().as_deref() {
                Some("podman") => Some("podman".to_string()),
                _ => Some("docker".to_string()),
            })
            .expect("container engine fallback should be set");

        Self { binary }
    }

    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        if let Ok(value) = std::env::var("OPENSHELL_E2E_CONTAINER_ENGINE_XDG_CONFIG_HOME") {
            command.env("XDG_CONFIG_HOME", value);
        } else if std::env::var_os("OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME").is_some()
        {
            command.env_remove("XDG_CONFIG_HOME");
        }
        command
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.binary
    }
}

#[must_use]
pub fn e2e_network_name() -> Option<String> {
    std::env::var("OPENSHELL_E2E_NETWORK_NAME")
        .ok()
        .or_else(|| std::env::var("OPENSHELL_E2E_DOCKER_NETWORK_NAME").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub struct ContainerHttpServer {
    pub host: String,
    pub port: u16,
    container_id: String,
    engine: ContainerEngine,
}

impl ContainerHttpServer {
    pub async fn start_python(alias: &str, script: &str) -> Result<Self, String> {
        let engine = ContainerEngine::from_env();
        let host_port = find_free_port();
        let network = e2e_network_name();
        let host = network.as_ref().map_or_else(
            || "host.openshell.internal".to_string(),
            |_| alias.to_string(),
        );
        let port = if network.is_some() { 8000 } else { host_port };

        let mut args = vec![
            "run".to_string(),
            "--detach".to_string(),
            "--rm".to_string(),
            "--entrypoint".to_string(),
            "python3".to_string(),
        ];
        if let Some(network) = network.as_deref() {
            args.extend([
                "--network".to_string(),
                network.to_string(),
                "--network-alias".to_string(),
                alias.to_string(),
            ]);
        } else {
            args.extend(["-p".to_string(), format!("{host_port}:8000")]);
        }
        args.extend([
            DEFAULT_TEST_SERVER_IMAGE.to_string(),
            "-c".to_string(),
            script.to_string(),
        ]);

        let output = engine
            .command()
            .args(&args)
            .output()
            .map_err(|e| format!("start {} test server: {e}", engine.name()))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(format!(
                "{} run failed (exit {:?}):\n{stderr}",
                engine.name(),
                output.status.code()
            ));
        }

        let server = Self {
            host,
            port,
            container_id: stdout,
            engine,
        };
        server.wait_until_ready().await?;
        Ok(server)
    }

    async fn wait_until_ready(&self) -> Result<(), String> {
        let container_id = self.container_id.clone();
        let engine = self.engine.clone();
        timeout(Duration::from_secs(60), async move {
            let mut tick = interval(Duration::from_millis(500));
            loop {
                tick.tick().await;
                let output = engine
                    .command()
                    .args([
                        "exec",
                        &container_id,
                        "python3",
                        "-c",
                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000', timeout=1).read()",
                    ])
                    .output()
                    .ok();
                if output.is_some_and(|o| o.status.success()) {
                    return;
                }
            }
        })
        .await
        .map_err(|_| {
            format!(
                "{} test server did not become ready within 60s",
                self.engine.name()
            )
        })
    }
}

impl Drop for ContainerHttpServer {
    fn drop(&mut self) {
        let _ = self
            .engine
            .command()
            .args(["rm", "-f", &self.container_id])
            .output();
    }
}
