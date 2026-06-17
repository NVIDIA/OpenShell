// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Container-engine helpers for Rust e2e tests.
//!
//! Most e2e tests should exercise the `OpenShell` gateway contract rather than a
//! specific local container runtime. This module keeps small support containers
//! and container-engine selection aligned between Docker- and Podman-backed
//! gateway runs.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use tokio::time::{interval, timeout};

use super::port::find_free_port;

const DEFAULT_TEST_SERVER_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";

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
    engine: String,
    binary: String,
}

impl ContainerEngine {
    pub fn from_env() -> Result<Self, String> {
        let resolved = resolve_container_engine(
            std::env::var("OPENSHELL_E2E_CONTAINER_ENGINE")
                .ok()
                .as_deref(),
            std::env::var("CONTAINER_ENGINE").ok().as_deref(),
            e2e_driver().as_deref(),
            &HostContainerEngineProbe,
        )?;

        Ok(Self {
            engine: resolved.engine,
            binary: resolved.binary,
        })
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
        &self.engine
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
        let engine = ContainerEngine::from_env()?;
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

fn normalized_env(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn validate_container_engine(name: &str, value: String) -> Result<String, String> {
    match value.as_str() {
        "docker" | "podman" => Ok(value),
        _ => Err(format!(
            "{name}={value} is invalid; expected docker or podman"
        )),
    }
}

fn required_engine_from_driver(driver: Option<&str>) -> Option<String> {
    match normalized_env(driver).as_deref() {
        Some("docker") => Some("docker".to_string()),
        Some("podman") => Some("podman".to_string()),
        _ => None,
    }
}

trait ContainerEngineProbe {
    fn command_exists(&self, command: &str) -> bool;
    fn docker_is_podman_shim(&self) -> bool;
}

struct HostContainerEngineProbe;

impl ContainerEngineProbe for HostContainerEngineProbe {
    fn command_exists(&self, command: &str) -> bool {
        command_exists(command)
    }

    fn docker_is_podman_shim(&self) -> bool {
        docker_is_podman_shim()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedContainerEngine {
    engine: String,
    binary: String,
}

impl ResolvedContainerEngine {
    fn new(engine: &str, binary: &str) -> Self {
        Self {
            engine: engine.to_string(),
            binary: binary.to_string(),
        }
    }
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        path.metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn command_exists(command: &str) -> bool {
    if command.contains(std::path::MAIN_SEPARATOR) {
        return is_executable_file(Path::new(command));
    }

    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| is_executable_file(&dir.join(command)))
    })
}

fn docker_is_podman_shim() -> bool {
    if !command_exists("docker") {
        return false;
    }

    let Ok(output) = Command::new("docker").arg("--version").output() else {
        return false;
    };
    let version = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    version.to_ascii_lowercase().contains("podman")
}

fn require_engine_available(
    engine: &str,
    probe: &impl ContainerEngineProbe,
) -> Result<ResolvedContainerEngine, String> {
    match engine {
        "docker" => {
            if !probe.command_exists("docker") {
                return Err(
                    "CONTAINER_ENGINE=docker requires the docker CLI to be installed and in PATH"
                        .to_string(),
                );
            }
            if probe.docker_is_podman_shim() {
                return Err(
                    "CONTAINER_ENGINE=docker was requested, but docker appears to be a Podman compatibility shim"
                        .to_string(),
                );
            }
            Ok(ResolvedContainerEngine::new("docker", "docker"))
        }
        "podman" => {
            if probe.command_exists("podman") {
                Ok(ResolvedContainerEngine::new("podman", "podman"))
            } else if probe.docker_is_podman_shim() {
                Ok(ResolvedContainerEngine::new("podman", "docker"))
            } else {
                Err(
                    "CONTAINER_ENGINE=podman requires the podman CLI or a docker-compatible Podman shim to be installed and in PATH"
                        .to_string(),
                )
            }
        }
        _ => Err(format!(
            "CONTAINER_ENGINE={engine} is invalid; expected docker or podman"
        )),
    }
}

fn auto_detect_container_engine(
    probe: &impl ContainerEngineProbe,
) -> Result<ResolvedContainerEngine, String> {
    if probe.command_exists("podman") {
        return Ok(ResolvedContainerEngine::new("podman", "podman"));
    }
    if probe.command_exists("docker") {
        if probe.docker_is_podman_shim() {
            return Ok(ResolvedContainerEngine::new("podman", "docker"));
        }
        return Ok(ResolvedContainerEngine::new("docker", "docker"));
    }

    Err("neither podman nor docker is installed; install one of them, or set CONTAINER_ENGINE=docker|podman".to_string())
}

fn resolve_container_engine(
    legacy_selector: Option<&str>,
    explicit_engine: Option<&str>,
    e2e_driver: Option<&str>,
    probe: &impl ContainerEngineProbe,
) -> Result<ResolvedContainerEngine, String> {
    if normalized_env(legacy_selector).is_some() {
        return Err(
            "OPENSHELL_E2E_CONTAINER_ENGINE is no longer supported; set CONTAINER_ENGINE=docker|podman instead"
                .to_string(),
        );
    }

    let explicit_engine = normalized_env(explicit_engine)
        .map(|value| validate_container_engine("CONTAINER_ENGINE", value))
        .transpose()?;
    let required_engine = required_engine_from_driver(e2e_driver);

    if let (Some(explicit), Some(required)) = (&explicit_engine, &required_engine)
        && explicit != required
    {
        return Err(format!(
            "CONTAINER_ENGINE={explicit} conflicts with OPENSHELL_E2E_DRIVER={required}; use CONTAINER_ENGINE={required} or unset CONTAINER_ENGINE"
        ));
    }

    if let Some(engine) = explicit_engine {
        require_engine_available(&engine, probe)
    } else if let Some(engine) = required_engine {
        require_engine_available(&engine, probe)
    } else {
        auto_detect_container_engine(probe)
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

#[cfg(test)]
mod tests {
    use super::{ContainerEngineProbe, ResolvedContainerEngine, resolve_container_engine};

    #[derive(Default)]
    struct FakeContainerEngineProbe {
        docker_exists: bool,
        podman_exists: bool,
        docker_is_podman_shim: bool,
    }

    impl ContainerEngineProbe for FakeContainerEngineProbe {
        fn command_exists(&self, command: &str) -> bool {
            match command {
                "docker" => self.docker_exists,
                "podman" => self.podman_exists,
                _ => false,
            }
        }

        fn docker_is_podman_shim(&self) -> bool {
            self.docker_exists && self.docker_is_podman_shim
        }
    }

    fn resolve(
        probe: &FakeContainerEngineProbe,
        legacy_selector: Option<&str>,
        explicit_engine: Option<&str>,
        e2e_driver: Option<&str>,
    ) -> Result<ResolvedContainerEngine, String> {
        resolve_container_engine(legacy_selector, explicit_engine, e2e_driver, probe)
    }

    fn docker() -> ResolvedContainerEngine {
        ResolvedContainerEngine::new("docker", "docker")
    }

    fn podman() -> ResolvedContainerEngine {
        ResolvedContainerEngine::new("podman", "podman")
    }

    fn podman_via_docker() -> ResolvedContainerEngine {
        ResolvedContainerEngine::new("podman", "docker")
    }

    #[test]
    fn defaults_to_auto_detected_podman_first() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        assert_eq!(resolve(&probe, None, None, None), Ok(podman()));
    }

    #[test]
    fn defaults_to_docker_when_podman_is_unavailable() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: false,
            docker_is_podman_shim: false,
        };

        assert_eq!(resolve(&probe, None, None, None), Ok(docker()));
    }

    #[test]
    fn defaults_to_logical_podman_when_docker_is_a_podman_shim() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: false,
            docker_is_podman_shim: true,
        };

        assert_eq!(resolve(&probe, None, None, None), Ok(podman_via_docker()));
    }

    #[test]
    fn fails_when_no_container_engine_is_available() {
        let probe = FakeContainerEngineProbe::default();

        let err = resolve(&probe, None, None, None).unwrap_err();
        assert!(err.contains("neither podman nor docker is installed"));
    }

    #[test]
    fn explicit_container_engine_wins_over_auto_detection() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        assert_eq!(resolve(&probe, None, Some("docker"), None), Ok(docker()));
    }

    #[test]
    fn explicit_podman_can_use_docker_compatibility_shim() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: false,
            docker_is_podman_shim: true,
        };

        assert_eq!(
            resolve(&probe, None, Some("podman"), None),
            Ok(podman_via_docker())
        );
    }

    #[test]
    fn explicit_docker_rejects_podman_compatibility_shim() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: false,
            docker_is_podman_shim: true,
        };

        let err = resolve(&probe, None, Some("docker"), None).unwrap_err();
        assert!(err.contains("docker appears to be a Podman compatibility shim"));
    }

    #[test]
    fn driver_selects_container_engine_without_explicit_engine() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        assert_eq!(resolve(&probe, None, None, Some("podman")), Ok(podman()));
    }

    #[test]
    fn rejects_removed_selector() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        let err = resolve(&probe, Some("podman"), None, None).unwrap_err();
        assert!(err.contains("OPENSHELL_E2E_CONTAINER_ENGINE"));
    }

    #[test]
    fn rejects_invalid_explicit_engine() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        let err = resolve(&probe, None, Some("containerd"), None).unwrap_err();
        assert!(err.contains("CONTAINER_ENGINE=containerd"));
    }

    #[test]
    fn rejects_explicit_driver_conflict() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        let err = resolve(&probe, None, Some("docker"), Some("podman")).unwrap_err();
        assert!(err.contains("CONTAINER_ENGINE=docker conflicts"));
    }

    #[test]
    fn ignores_non_container_drivers_and_auto_detects() {
        let probe = FakeContainerEngineProbe {
            docker_exists: true,
            podman_exists: true,
            docker_is_podman_shim: false,
        };

        assert_eq!(
            resolve(&probe, None, None, Some("kubernetes")),
            Ok(podman())
        );
    }
}
