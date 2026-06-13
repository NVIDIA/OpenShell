// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI backend for Apple's installed `container` command.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Error returned while running Apple's `container` CLI.
#[derive(Debug, thiserror::Error)]
pub enum AppleContainerCliError {
    /// A command could not be started.
    #[error("failed to execute `{program}`: {source}")]
    Spawn {
        /// Program path attempted by the backend.
        program: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A command exited unsuccessfully.
    #[error("`{program} {args}` failed with status {status}: {stderr}")]
    Status {
        /// Program path attempted by the backend.
        program: String,
        /// Command-line arguments, shell-escaped for diagnostics only.
        args: String,
        /// Exit status text.
        status: String,
        /// Standard error text.
        stderr: String,
    },
    /// Command output could not be decoded as UTF-8.
    #[error("decode `{program}` stdout failed: {source}")]
    Utf8 {
        /// Program path attempted by the backend.
        program: String,
        /// Underlying UTF-8 error.
        source: std::string::FromUtf8Error,
    },
    /// Command output JSON did not match the expected schema.
    #[error("parse `{program}` JSON failed: {source}")]
    Json {
        /// Program path attempted by the backend.
        program: String,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// Apple Container service is reachable but not ready to run containers.
    #[error("`{program} system status --format json` reported status {status}")]
    Unhealthy {
        /// Program path attempted by the backend.
        program: String,
        /// Service status returned by Apple Container.
        status: String,
    },
}

/// JSON status produced by `container system status --format json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerSystemStatus {
    /// Service state such as `running`.
    pub status: String,
}

/// JSON container entry produced by `container list --format json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerListEntry {
    /// Apple container identifier.
    pub id: String,
    /// Static container configuration.
    pub configuration: AppleContainerConfiguration,
    /// Runtime status.
    pub status: AppleContainerStatus,
}

/// Static configuration fields used by the driver.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerConfiguration {
    /// Creation timestamp emitted by Apple Container.
    #[serde(default, rename = "creationDate")]
    pub creation_date: Option<String>,
    /// Container labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Image metadata.
    pub image: Option<AppleContainerImage>,
}

/// Image metadata emitted by Apple container.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerImage {
    /// Original image reference.
    pub reference: String,
}

/// Runtime status fields used by the driver.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerStatus {
    /// Runtime state such as `running` or `stopped`.
    pub state: String,
}

/// JSON network entry produced by `container network list --format json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerNetworkEntry {
    /// Apple network identifier.
    pub id: String,
    /// Static network configuration.
    pub configuration: AppleContainerNetworkConfiguration,
    /// Runtime network status.
    pub status: AppleContainerNetworkStatus,
}

/// Static network configuration fields used by the driver.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerNetworkConfiguration {
    /// Network name.
    pub name: String,
}

/// Runtime network status fields used by the driver.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleContainerNetworkStatus {
    /// IPv4 host-side gateway address for the Apple vmnet network.
    #[serde(default, rename = "ipv4Gateway")]
    pub ipv4_gateway: Option<IpAddr>,
}

/// Apple Container CLI wrapper.
#[derive(Debug, Clone)]
pub struct AppleContainerCli {
    program: PathBuf,
}

impl AppleContainerCli {
    /// Create a CLI backend using the configured executable path.
    #[must_use]
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    /// Run `container system status --format json` to verify the service is ready.
    pub async fn health(&self) -> Result<(), AppleContainerCliError> {
        let status = self.system_status().await?;
        if status.status.trim().eq_ignore_ascii_case("running") {
            Ok(())
        } else {
            Err(AppleContainerCliError::Unhealthy {
                program: self.program.display().to_string(),
                status: status.status,
            })
        }
    }

    /// Return the Apple Container service status as machine-readable JSON.
    pub async fn system_status(
        &self,
    ) -> Result<AppleContainerSystemStatus, AppleContainerCliError> {
        let text = self.run(["system", "status", "--format", "json"]).await?;
        serde_json::from_str(&text).map_err(|source| AppleContainerCliError::Json {
            program: self.program.display().to_string(),
            source,
        })
    }

    /// Create and start a detached container.
    ///
    /// Apple Container exposes `create` and `start` as separate commands, but
    /// listing the container between those two calls reports a stopped state.
    /// `run --detach` keeps normal sandbox provisioning as a single visible
    /// lifecycle transition from absent to running.
    pub async fn run_detached(&self, args: &[String]) -> Result<(), AppleContainerCliError> {
        let mut command_args = vec!["run".to_string(), "--detach".to_string()];
        command_args.extend_from_slice(args);
        self.run(command_args).await.map(|_| ())
    }

    /// Start a container.
    pub async fn start(&self, id: &str) -> Result<(), AppleContainerCliError> {
        self.run(["start", id]).await.map(|_| ())
    }

    /// Stop a container.
    pub async fn stop(&self, id: &str, timeout_secs: u32) -> Result<(), AppleContainerCliError> {
        self.run(["stop", "--time", &timeout_secs.to_string(), id])
            .await
            .map(|_| ())
    }

    /// Delete a container.
    pub async fn delete(&self, id: &str) -> Result<bool, AppleContainerCliError> {
        match self.run(["delete", "--force", id]).await {
            Ok(_) => Ok(true),
            Err(AppleContainerCliError::Status { stderr, .. })
                if stderr.contains("not found") || stderr.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    /// Create a named Apple container volume.
    pub async fn create_volume(
        &self,
        name: &str,
        labels: &[String],
    ) -> Result<(), AppleContainerCliError> {
        let mut argv = vec!["volume".to_string(), "create".to_string()];
        for label in labels {
            argv.push("--label".to_string());
            argv.push(label.clone());
        }
        argv.push(name.to_string());
        self.run(argv).await.map(|_| ())
    }

    /// Delete a named Apple container volume.
    pub async fn delete_volume(&self, name: &str) -> Result<bool, AppleContainerCliError> {
        match self.run(["volume", "delete", name]).await {
            Ok(_) => Ok(true),
            Err(AppleContainerCliError::Status { stderr, .. })
                if stderr.contains("not found") || stderr.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    /// List all containers.
    pub async fn list(&self) -> Result<Vec<AppleContainerListEntry>, AppleContainerCliError> {
        let text = self.run(["list", "--all", "--format", "json"]).await?;
        serde_json::from_str(&text).map_err(|source| AppleContainerCliError::Json {
            program: self.program.display().to_string(),
            source,
        })
    }

    /// List Apple Container networks as machine-readable JSON.
    pub async fn list_networks(
        &self,
    ) -> Result<Vec<AppleContainerNetworkEntry>, AppleContainerCliError> {
        let text = self.run(["network", "list", "--format", "json"]).await?;
        serde_json::from_str(&text).map_err(|source| AppleContainerCliError::Json {
            program: self.program.display().to_string(),
            source,
        })
    }

    async fn run<I, S>(&self, args: I) -> Result<String, AppleContainerCliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect::<Vec<_>>();
        let output = Command::new(&self.program)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|source| AppleContainerCliError::Spawn {
                program: self.program.display().to_string(),
                source,
            })?;
        if !output.status.success() {
            return Err(AppleContainerCliError::Status {
                program: self.program.display().to_string(),
                args: redact_args(&args),
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        String::from_utf8(output.stdout).map_err(|source| AppleContainerCliError::Utf8 {
            program: self.program.display().to_string(),
            source,
        })
    }
}

/// Build an Apple `--mount` argument for a read-only bind mount.
#[must_use]
pub fn readonly_bind_mount(source: &Path, target: &str) -> String {
    format!(
        "type=bind,source={},target={target},readonly",
        source.display()
    )
}

fn redact_args(args: &[String]) -> String {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next_env = false;
    for arg in args {
        if redact_next_env {
            redacted.push(redact_env_arg(arg));
            redact_next_env = false;
        } else {
            redact_next_env = arg == "--env";
            redacted.push(arg.clone());
        }
    }
    redacted.join(" ")
}

fn redact_env_arg(arg: &str) -> String {
    arg.split_once('=').map_or_else(
        || "<redacted>".to_string(),
        |(key, _)| format!("{key}=<redacted>"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_args_redact_environment_values() {
        let args = vec![
            "run".to_string(),
            "--env".to_string(),
            "TOKEN=secret".to_string(),
            "--name".to_string(),
            "demo".to_string(),
        ];

        assert_eq!(redact_args(&args), "run --env TOKEN=<redacted> --name demo");
    }

    #[test]
    fn parses_system_status_json() {
        let status: AppleContainerSystemStatus =
            serde_json::from_str(r#"{"status":"running"}"#).unwrap();

        assert_eq!(status.status, "running");
    }

    #[test]
    fn parses_container_list_json() {
        let entries: Vec<AppleContainerListEntry> = serde_json::from_str(
            r#"[
                {
                    "id": "openshell-demo",
                    "configuration": {
                        "creationDate": "2026-06-12T08:00:00Z",
                        "labels": {
                            "io.openshell.managed-by": "openshell",
                            "io.openshell.sandbox-id": "sandbox-1"
                        },
                        "image": {
                            "reference": "ghcr.io/nvidia/openshell/sandbox:latest"
                        }
                    },
                    "status": {
                        "state": "running"
                    }
                }
            ]"#,
        )
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "openshell-demo");
        assert_eq!(
            entries[0].configuration.labels["io.openshell.sandbox-id"],
            "sandbox-1"
        );
        assert_eq!(
            entries[0]
                .configuration
                .image
                .as_ref()
                .map(|image| image.reference.as_str()),
            Some("ghcr.io/nvidia/openshell/sandbox:latest")
        );
        assert_eq!(entries[0].status.state, "running");
    }

    #[test]
    fn parses_network_list_json() {
        let networks: Vec<AppleContainerNetworkEntry> = serde_json::from_str(
            r#"[
                {
                    "id": "default",
                    "configuration": {
                        "name": "default"
                    },
                    "status": {
                        "ipv4Gateway": "192.168.64.1"
                    }
                }
            ]"#,
        )
        .unwrap();

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].configuration.name, "default");
        assert_eq!(
            networks[0].status.ipv4_gateway.map(|ip| ip.to_string()),
            Some("192.168.64.1".to_string())
        );
    }
}
